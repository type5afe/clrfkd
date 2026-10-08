// Package engine runs the scan for a single target.
//
// The order of work is what keeps the request count down:
//
//  1. One baseline request. If the host does not answer, the target is dropped
//     without spending a single probe on it. On a list harvested from an
//     archive, where many hosts are long dead, this is most of the saving.
//  2. Probes, ordered so that the encodings that actually find bugs go first.
//  3. A confirmation request for anything that looks positive, before it is
//     reported.
//
// Step 3 is the difference between a finding and a guess. A single response can
// look vulnerable because it came from a cache, because one host behind a load
// balancer differs, or because a parameter happened to land in a header that
// run. Sending the same probe twice and requiring the same verdict costs one
// request per candidate and removes that whole class of false positive.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/type5afe/clrfkd/internal/detect"
	"github.com/type5afe/clrfkd/internal/httpx"
	"github.com/type5afe/clrfkd/internal/inject"
	"github.com/type5afe/clrfkd/internal/payload"
)

// Config controls a scan.
type Config struct {
	Method     string
	Body       string
	Headers    http.Header
	Tier       int
	Kinds      []inject.Kind
	Split      bool
	All        bool // report every working payload instead of stopping at the first
	Verify     bool
	ProbeConc  int
	Delay      time.Duration
	ReportInfo bool // include reflection classes, which are not vulnerabilities
}

// Finding is one reportable result.
type Finding struct {
	Time       time.Time `json:"time"`
	Target     string    `json:"target"`
	URL        string    `json:"url"`
	Method     string    `json:"method"`
	Sink       string    `json:"sink"`
	PayloadID  string    `json:"payload_id"`
	Payload    string    `json:"payload"`
	Class      string    `json:"class"`
	Severity   string    `json:"severity"`
	Confidence string    `json:"confidence"`
	Status     int       `json:"status"`
	Responses  int       `json:"responses_on_wire"`
	Evidence   string    `json:"evidence"`
	Curl       string    `json:"curl"`
}

// Vulnerable reports whether the finding is an injection rather than an
// observation about where the payload landed.
func (f Finding) Vulnerable() bool { return detect.Class(f.Class).Vulnerable() }

// Result is the outcome for one target.
type Result struct {
	Target   string
	Findings []Finding
	Requests int
	Err      error
}

// Engine scans targets with a fixed configuration and canary.
type Engine struct {
	cfg      Config
	client   *httpx.Client
	canary   payload.Canary
	payloads []payload.Payload
}

// New builds an Engine.
func New(cfg Config, client *httpx.Client, canary payload.Canary) *Engine {
	if cfg.ProbeConc < 1 {
		cfg.ProbeConc = 1
	}
	if len(cfg.Kinds) == 0 {
		cfg.Kinds = inject.AllKinds
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodGet
	}
	return &Engine{
		cfg:      cfg,
		client:   client,
		canary:   canary,
		payloads: payload.Set(cfg.Tier, cfg.Split, canary),
	}
}

// Payloads returns the payload set in use, for reporting.
func (e *Engine) Payloads() []payload.Payload { return e.payloads }

// Scan probes one target.
func (e *Engine) Scan(ctx context.Context, raw string) Result {
	res := Result{Target: raw}

	u, err := Normalize(raw)
	if err != nil {
		res.Err = err
		return res
	}

	// Baseline. Establishes that the host answers at all, and gives the probes
	// something to be compared against.
	base := inject.Request{Path: pathOf(u), Query: u.RawQuery, Body: e.cfg.Body}
	if _, err := e.send(ctx, u, base); err != nil {
		res.Requests++
		res.Err = fmt.Errorf("baseline: %w", err)
		return res
	}
	res.Requests++

	points := inject.Points(u, e.cfg.Body, e.cfg.Kinds)
	if len(points) == 0 {
		return res
	}

	type job struct {
		pt  inject.Point
		pay payload.Payload
	}
	jobs := make(chan job)
	var (
		mu       sync.Mutex
		stop     atomic.Bool
		claimed  atomic.Bool
		requests atomic.Int64
		found    []Finding
		wg       sync.WaitGroup
	)

	for i := 0; i < e.cfg.ProbeConc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if stop.Load() || ctx.Err() != nil {
					continue
				}
				if e.cfg.Delay > 0 {
					select {
					case <-ctx.Done():
						continue
					case <-time.After(e.cfg.Delay):
					}
				}
				cand, n, ok := e.probe(ctx, u, j.pt, j.pay)
				requests.Add(int64(n))
				if !ok {
					continue
				}
				// Concurrent probes routinely hit in the same instant. Without
				// --all only one of them needs confirming and reporting; the
				// others would each spend a request re-proving the same bug.
				if cand.Vulnerable() && !e.cfg.All {
					if !claimed.CompareAndSwap(false, true) {
						continue
					}
					// The decision to stop is already made, so stop feeding
					// before spending the confirmation request rather than
					// after it.
					stop.Store(true)
				}
				if cand.Vulnerable() && e.cfg.Verify {
					requests.Add(int64(e.verify(ctx, u, j.pt, j.pay, &cand)))
				}
				mu.Lock()
				found = append(found, cand)
				mu.Unlock()
			}
		}()
	}

	// Payload-major order: try the most promising encoding at every sink
	// before moving to a weaker one, so an early exit happens as soon as
	// possible.
outer:
	for _, pay := range e.payloads {
		for _, pt := range points {
			if stop.Load() || ctx.Err() != nil {
				break outer
			}
			select {
			case jobs <- job{pt: pt, pay: pay}:
			case <-ctx.Done():
				break outer
			}
		}
	}
	close(jobs)
	wg.Wait()

	res.Requests += int(requests.Load())
	res.Findings = finalize(rank(found), e.cfg.All)
	return res
}

// probe sends one payload at one point and reports what came back. It does not
// confirm the result; the caller decides whether this candidate is the one
// worth spending a confirmation request on.
func (e *Engine) probe(ctx context.Context, u *url.URL, pt inject.Point, pay payload.Payload) (Finding, int, bool) {
	req := inject.Build(u, e.cfg.Body, pt, pay.Value)
	n := 1

	resp, err := e.send(ctx, u, req)
	if err != nil {
		if errors.Is(err, httpx.ErrNotSent) {
			return Finding{}, 0, false
		}
		return Finding{}, n, false
	}
	hit, ok := detect.Analyze(resp.Wire, e.canary)
	if !ok {
		return Finding{}, n, false
	}
	if !hit.Class.Vulnerable() && !e.cfg.ReportInfo {
		return Finding{}, n, false
	}
	confidence := "unverified"

	full := u.Scheme + "://" + u.Host + req.Path
	if req.Query != "" {
		full += "?" + req.Query
	}

	return Finding{
		Time:       time.Now().UTC(),
		Target:     u.String(),
		URL:        full,
		Method:     e.cfg.Method,
		Sink:       pt.String(),
		PayloadID:  pay.ID,
		Payload:    pay.Value,
		Class:      string(hit.Class),
		Severity:   string(hit.Severity),
		Confidence: confidence,
		Status:     resp.Status,
		Responses:  hit.Responses,
		Evidence:   hit.Evidence,
		Curl:       curlFor(e.cfg.Method, full, req.Body, e.cfg.Headers),
	}, n, true
}

// verify re-sends a probe and requires the same verdict before the finding is
// reported as confirmed. One extra request removes the false positives that
// come from caches, from one host in a pool differing from its peers, and from
// a response that simply varied that run.
func (e *Engine) verify(ctx context.Context, u *url.URL, pt inject.Point, pay payload.Payload, f *Finding) int {
	if !e.cfg.Verify {
		return 0
	}
	f.Confidence = "unconfirmed"
	resp, err := e.send(ctx, u, inject.Build(u, e.cfg.Body, pt, pay.Value))
	if err != nil {
		if errors.Is(err, httpx.ErrNotSent) {
			return 0
		}
		return 1
	}
	if hit, ok := detect.Analyze(resp.Wire, e.canary); ok && string(hit.Class) == f.Class {
		f.Confidence = "confirmed"
	}
	return 1
}

// finalize trims the finding list to what the flags promise: one finding per
// target by default, every working payload with --all. Informational findings
// are always collapsed per class and sink, because the same reflection
// otherwise repeats once for every payload tried.
func finalize(f []Finding, all bool) []Finding {
	if len(f) == 0 {
		return nil
	}
	if !all {
		for _, x := range f {
			if x.Vulnerable() {
				return []Finding{x}
			}
		}
	}
	seen := map[string]bool{}
	var out []Finding
	for _, x := range f {
		if !x.Vulnerable() {
			k := x.Class + "|" + x.Sink
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		out = append(out, x)
	}
	return out
}

func (e *Engine) send(ctx context.Context, u *url.URL, r inject.Request) (*httpx.Response, error) {
	return e.client.Do(ctx, httpx.Request{
		Method:  e.cfg.Method,
		Base:    u,
		Path:    r.Path,
		Query:   r.Query,
		Body:    r.Body,
		Headers: e.cfg.Headers,
	})
}

func pathOf(u *url.URL) string {
	if u.RawPath != "" {
		return u.RawPath
	}
	if u.Path == "" {
		return "/"
	}
	return u.EscapedPath()
}

// Normalize parses and validates a target, defaulting a missing scheme to
// https so that bare hostnames from a subdomain list can be fed straight in.
func Normalize(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "info": 3}

func rank(f []Finding) []Finding {
	if len(f) < 2 {
		return f
	}
	out := append([]Finding(nil), f...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && severityRank[out[j].Severity] < severityRank[out[j-1].Severity]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// curlFor renders a copy-pasteable reproduction. The flags matter: -g stops
// curl interpreting braces and brackets as globs, and --path-as-is stops it
// collapsing the traversal sequences some payloads rely on.
func curlFor(method, full, body string, headers http.Header) string {
	var b strings.Builder
	b.WriteString("curl -gsSik --path-as-is")
	if method != http.MethodGet {
		b.WriteString(" -X " + method)
	}
	for k, vs := range headers {
		for _, v := range vs {
			b.WriteString(" -H " + shQuote(k+": "+v))
		}
	}
	if body != "" {
		b.WriteString(" --data-raw " + shQuote(body))
	}
	b.WriteString(" -i " + shQuote(full))
	return b.String()
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
