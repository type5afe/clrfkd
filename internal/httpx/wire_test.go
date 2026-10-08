package httpx

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rawServer captures the exact first line of each request it receives.
func rawServer(t *testing.T, reply string) (base string, lines <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 8)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				first, err := br.ReadString('\n')
				if err != nil {
					return
				}
				ch <- strings.TrimRight(first, "\r\n")
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				io.WriteString(c, reply)
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), ch
}

// The whole scanner rests on payloads reaching the wire byte-for-byte. If
// net/http re-encoded or path-cleaned the request target, every probe would be
// testing something other than what it reports.
func TestRequestLineIsVerbatim(t *testing.T) {
	base, lines := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	u, _ := url.Parse(base)
	c, err := New(Config{Timeout: 3 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, path, query, want string
	}{
		{"percent CRLF in path", "/a%0d%0aX-H%3a%20v", "", "GET /a%0d%0aX-H%3a%20v HTTP/1.1"},
		{"uppercase hex preserved", "/a%0D%0AX-H%3A%20v", "", "GET /a%0D%0AX-H%3A%20v HTTP/1.1"},
		{"double encoding preserved", "/a%250d%250a", "", "GET /a%250d%250a HTTP/1.1"},
		{"overlong utf8 preserved", "/a%c0%8d%c0%8a", "", "GET /a%c0%8d%c0%8a HTTP/1.1"},
		{"cjk unicode preserved", "/a%e5%98%8d%e5%98%8a", "", "GET /a%e5%98%8d%e5%98%8a HTTP/1.1"},
		{"traversal not cleaned", "/a/..%2f..%2fb%0d%0a", "", "GET /a/..%2f..%2fb%0d%0a HTTP/1.1"},
		{"raw dotdot not cleaned", "/a/../../b", "", "GET /a/../../b HTTP/1.1"},
		{"query preserved with path", "/p", "next=/home%0d%0aX-H%3a%20v", "GET /p?next=/home%0d%0aX-H%3a%20v HTTP/1.1"},
		{"null byte preserved", "/a%00%0d%0a", "", "GET /a%00%0d%0a HTTP/1.1"},
		{"invalid hex kept as-is", "/a%zz%0d%0a", "", "GET /a%zz%0d%0a HTTP/1.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Do(context.Background(), Request{
				Method: "GET", Base: u, Path: tc.path, Query: tc.query,
			})
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			select {
			case got := <-lines:
				if got != tc.want {
					t.Errorf("request line\n got: %q\nwant: %q", got, tc.want)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("server never saw the request")
			}
		})
	}
}

// The capture buffer must hold the injected second response that net/http
// discards, or the highest-severity class could never be detected.
func TestWireCaptureKeepsSplitResponse(t *testing.T) {
	const reply = "HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nCANARY1"
	base, _ := rawServer(t, reply)
	u, _ := url.Parse(base)
	c, _ := New(Config{Timeout: 3 * time.Second}, nil)

	res, err := c.Do(context.Background(), Request{Method: "GET", Base: u, Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 302 {
		t.Errorf("parsed status = %d, want 302", res.Status)
	}
	if !strings.Contains(string(res.Wire), "CANARY1") {
		t.Fatalf("injected response missing from wire capture: %q", res.Wire)
	}
	if n := strings.Count(string(res.Wire), "HTTP/1.1"); n != 2 {
		t.Errorf("status lines on wire = %d, want 2", n)
	}
}

// forwardProxy reports the request line it is handed, so a test can assert the
// form of a proxied request.
func forwardProxy(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 4)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				first, err := br.ReadString('\n')
				if err != nil {
					return
				}
				ch <- strings.TrimRight(first, "\r\n")
				for {
					l, e := br.ReadString('\n')
					if e != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), ch
}

// Running through Burp is a primary workflow, and a forward proxy needs the
// absolute form of the target. Setting URL.Opaque to control the request line
// suppresses net/http's own rewrite, so the client has to do it, and it still
// has to preserve the payload byte for byte.
func TestProxiedRequestUsesAbsoluteForm(t *testing.T) {
	pxy, lines := forwardProxy(t)
	c, err := New(Config{Timeout: 3 * time.Second, Proxy: pxy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("http://target.tld/hdr")
	if _, err := c.Do(context.Background(), Request{
		Method: "GET", Base: base,
		Path:  "/hdr%0d%0aX-H%3a%20v",
		Query: "next=/home",
	}); err != nil {
		t.Fatalf("request: %v", err)
	}
	select {
	case got := <-lines:
		want := "GET http://target.tld/hdr%0d%0aX-H%3a%20v?next=/home HTTP/1.1"
		if got != want {
			t.Errorf("proxy saw\n got: %q\nwant: %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy never saw the request")
	}
}

// Without a proxy the target must stay in origin form.
func TestDirectRequestUsesOriginForm(t *testing.T) {
	base, lines := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	u, _ := url.Parse(base)
	c, _ := New(Config{Timeout: 3 * time.Second}, nil)
	if _, err := c.Do(context.Background(), Request{
		Method: "GET", Base: u, Path: "/a%0d%0aX-H%3a%20v",
	}); err != nil {
		t.Fatal(err)
	}
	if got := <-lines; got != "GET /a%0d%0aX-H%3a%20v HTTP/1.1" {
		t.Errorf("request line = %q", got)
	}
}
