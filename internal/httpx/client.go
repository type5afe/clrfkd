// Package httpx is the HTTP client used for probing.
//
// It is an ordinary net/http client with two deliberate differences.
//
// First, every byte read from the socket is captured. net/http gives a clean,
// well-tested parse of the response, but it also throws away anything the
// response's own framing says is not part of the message, which is exactly
// where an injected second response lives. Teeing the connection keeps both.
//
// Second, HTTP/2 is disabled. CRLF injection is a property of HTTP/1.x framing:
// in HTTP/2 headers are length-prefixed binary fields and a stray CR or LF
// cannot terminate one. Negotiating h2 would silently make targets look safe.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures a Client.
type Config struct {
	Timeout   time.Duration
	Retries   int
	Proxy     string
	TLSVerify bool
	Follow    bool
	// MaxBody caps how much of the body is read. Enough is needed to catch a
	// split that lands in the body, but a scanner should not buffer a 2GB file.
	MaxBody int64
}

// Client performs probe requests.
type Client struct {
	hc      *http.Client
	cfg     Config
	limiter *Limiter
	proxied bool
}

type captureKey struct{}

// capture accumulates the raw bytes read from one connection.
type capture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capture) Write(p []byte) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
}

func (c *capture) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// teeConn records everything read from the underlying connection.
type teeConn struct {
	net.Conn
	cap *capture
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.cap.Write(p[:n])
	}
	return n, err
}

// New builds a Client. A nil limiter means no rate limiting.
func New(cfg Config, limiter *Limiter) (*Client, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 512 << 10
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// One probe per connection. Responses must map one-to-one onto a
		// capture buffer, and a reused connection would mix two together.
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !cfg.TLSVerify},
		TLSHandshakeTimeout: cfg.Timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if cp, ok := ctx.Value(captureKey{}).(*capture); ok {
				return &teeConn{Conn: c, cap: cp}, nil
			}
			return c, nil
		},
	}
	proxied := false
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", cfg.Proxy, err)
		}
		tr.Proxy = http.ProxyURL(pu)
		proxied = true
	}

	redirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if cfg.Follow {
		redirect = nil
	}
	return &Client{
		hc:      &http.Client{Transport: tr, CheckRedirect: redirect, Timeout: cfg.Timeout},
		cfg:     cfg,
		limiter: limiter,
		proxied: proxied,
	}, nil
}

// Request is one probe to send. Path and Query are written to the request line
// verbatim; see package inject.
type Request struct {
	Method  string
	Base    *url.URL
	Path    string
	Query   string
	Body    string
	Headers http.Header
}

// Response is the outcome of a probe.
type Response struct {
	Status int
	Header http.Header
	Wire   []byte // raw bytes read from the socket
	Target string // request line as sent, for reporting
}

// ErrNotSent wraps the error returned when a probe was abandoned before any
// bytes left the machine, so that callers can keep an honest count of the
// requests a scan actually cost.
var ErrNotSent = errors.New("request not sent")

// Do sends a request, retrying on transport errors and on the status codes that
// mean "ask again later". The capture buffer is per attempt.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		if attempt > 0 {
			// Exponential backoff, capped. A target that is rate-limiting us
			// is a target we should slow down for, not hammer.
			wait := time.Duration(1<<uint(attempt-1)) * 250 * time.Millisecond
			if wait > 4*time.Second {
				wait = 4 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %w", ErrNotSent, ctx.Err())
			case <-time.After(wait):
			}
		}
		if c.limiter != nil {
			if err := c.limiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrNotSent, err)
			}
		}
		res, err := c.do(ctx, r)
		if err == nil && !shouldRetry(res.Status) {
			return res, nil
		}
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		lastErr = fmt.Errorf("status %d", res.Status)
		if attempt == c.cfg.Retries {
			return res, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastErr
}

func shouldRetry(status int) bool {
	return status == 429 || status == 503 || status == 502 || status == 504
}

func (c *Client) do(ctx context.Context, r Request) (*Response, error) {
	cp := &capture{}
	ctx = context.WithValue(ctx, captureKey{}, cp)

	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.Base.String(), body)
	if err != nil {
		return nil, err
	}
	// Opaque and RawQuery are emitted verbatim by URL.RequestURI, which is the
	// only way to put a payload on the wire without net/http normalising it.
	//
	// Setting Opaque also suppresses net/http's own rewrite of the request
	// target into absolute form for proxied requests, so that has to be done
	// here. It applies to cleartext requests only: an https request through a
	// proxy is tunnelled with CONNECT and then carries an origin-form target
	// inside the tunnel.
	req.URL.Opaque = r.Path
	if c.proxied && r.Base.Scheme == "http" {
		req.URL.Opaque = r.Base.Scheme + "://" + r.Base.Host + r.Path
	}
	req.URL.RawQuery = r.Query
	req.URL.Fragment = ""
	req.URL.RawFragment = ""

	for k, vs := range r.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}
	if r.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	target := r.Path
	if r.Query != "" {
		target += "?" + r.Query
	}
	res, err := c.hc.Do(req)
	if err != nil {
		// A transport error is still worth reporting if bytes came back: a
		// malformed injected response is itself evidence.
		if w := cp.bytes(); len(w) > 0 {
			return &Response{Wire: w, Target: target}, nil
		}
		return nil, err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, c.cfg.MaxBody))

	return &Response{
		Status: res.StatusCode,
		Header: res.Header,
		Wire:   cp.bytes(),
		Target: target,
	}, nil
}

// DefaultUserAgent is sent unless the caller overrides it. It names the tool
// so that the owner of a scanned host can identify the traffic in their logs.
const DefaultUserAgent = "clrfkd (+https://github.com/type5afe/clrfkd)"
