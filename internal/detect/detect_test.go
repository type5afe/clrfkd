package detect

import (
	"strconv"
	"testing"

	"github.com/type5afe/clrfkd/internal/payload"
)

var can = payload.Canary{Header: "X-Clrfkd-dead", Value: "beef1234"}

func TestAnalyze(t *testing.T) {
	cases := []struct {
		name     string
		wire     string
		wantHit  bool
		wantCls  Class
		wantSev  Severity
		wantVuln bool
	}{
		{
			name:     "canary arrives as its own header",
			wire:     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Clrfkd-dead: beef1234\r\n\r\nok",
			wantHit:  true,
			wantCls:  HeaderInject,
			wantSev:  High,
			wantVuln: true,
		},
		{
			name: "second response on the wire is splitting",
			wire: "HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n<html>beef1234</html>",
			wantHit:  true,
			wantCls:  ResponseSplit,
			wantSev:  Critical,
			wantVuln: true,
		},
		{
			name:     "bare LF framing is honoured",
			wire:     "HTTP/1.1 200 OK\nContent-Length: 2\nX-Clrfkd-dead: beef1234\n\nok",
			wantHit:  true,
			wantCls:  HeaderInject,
			wantSev:  High,
			wantVuln: true,
		},
		{
			name:     "canary in Set-Cookie is cookie injection",
			wire:     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: sid=beef1234\r\n\r\nok",
			wantHit:  true,
			wantCls:  CookieInject,
			wantSev:  High,
			wantVuln: true,
		},
		{
			// The payload reached a header but its CRLF stayed encoded. A sink
			// worth another encoding, not a vulnerability.
			name:     "payload echoed inside a header value is filtered, not injected",
			wire:     "HTTP/1.1 302 Found\r\nLocation: /a%0d%0aX-Clrfkd-dead:%20beef1234\r\nContent-Length: 0\r\n\r\n",
			wantHit:  true,
			wantCls:  HeaderReflect,
			wantSev:  Medium,
			wantVuln: false,
		},
		{
			// An error page that echoes the URL is the classic false positive.
			name:     "payload echoed in the body only is reflection",
			wire:     "HTTP/1.1 404 Not Found\r\nContent-Length: 40\r\n\r\n<p>no such page: /a%0d%0abeef1234</p>",
			wantHit:  true,
			wantCls:  BodyReflect,
			wantSev:  Info,
			wantVuln: false,
		},
		{
			name:    "clean response is not a hit",
			wire:    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			wantHit: false,
		},
		{
			name:    "empty wire is not a hit",
			wire:    "",
			wantHit: false,
		},
		{
			// Two responses but neither contains our canary: pipelining or a
			// proxy artefact, not our injection.
			name: "second response without the canary is not reported",
			wire: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
			wantHit: false,
		},
		{
			name:     "header name match is case insensitive",
			wire:     "HTTP/1.1 200 OK\r\nx-clrfkd-dead: beef1234\r\nContent-Length: 0\r\n\r\n",
			wantHit:  true,
			wantCls:  HeaderInject,
			wantVuln: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Analyze([]byte(tc.wire), can)
			if ok != tc.wantHit {
				t.Fatalf("hit = %v, want %v (result %+v)", ok, tc.wantHit, got)
			}
			if !tc.wantHit {
				return
			}
			if got.Class != tc.wantCls {
				t.Errorf("class = %q, want %q", got.Class, tc.wantCls)
			}
			if tc.wantSev != "" && got.Severity != tc.wantSev {
				t.Errorf("severity = %q, want %q", got.Severity, tc.wantSev)
			}
			if got.Class.Vulnerable() != tc.wantVuln {
				t.Errorf("Vulnerable() = %v, want %v", got.Class.Vulnerable(), tc.wantVuln)
			}
			if got.Evidence == "" {
				t.Error("hit carries no evidence")
			}
		})
	}
}

func TestSplitHeaderRejectsNonHeaders(t *testing.T) {
	if _, _, ok := splitHeader("not a header"); ok {
		t.Error("accepted a line with no colon")
	}
	if _, _, ok := splitHeader("bad name: v"); ok {
		t.Error("accepted a name containing a space")
	}
	if _, _, ok := splitHeader(":novalue"); ok {
		t.Error("accepted an empty name")
	}
	n, v, ok := splitHeader("X-A:  b c ")
	if !ok || n != "X-A" || v != "b c" {
		t.Errorf("got %q/%q/%v", n, v, ok)
	}
}

// resp assembles a response with a correct Content-Length, so the framing says
// the body really does contain everything after the blank line.
func resp(status, extraHeaders, body string) string {
	h := "HTTP/1.1 " + status + "\r\n"
	if extraHeaders != "" {
		h += extraHeaders + "\r\n"
	}
	return h + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// The --split payloads write a literal "HTTP/1.1 200 OK" into the request. A
// page that echoes the payload back therefore returns something that looks
// exactly like a split response but is only body text, and calling that
// critical would be a serious false positive. The first message's own framing
// is what tells the two apart.
func TestEchoedResponseInsideBodyIsNotASplit(t *testing.T) {
	body := "<p>you searched for: HTTP/1.1 200 OK\r\n" +
		can.Header + ": " + can.Value + "\r\n\r\n<html>" + can.Value + "</html></p>"
	got, ok := Analyze([]byte(resp("200 OK", "Content-Type: text/html", body)), can)
	if !ok {
		t.Fatal("expected the reflection to be noticed")
	}
	if got.Class == ResponseSplit {
		t.Fatalf("echoed payload inside the declared body reported as %s", got.Class)
	}
	if got.Class != BodyReflect {
		t.Errorf("class = %q, want body-reflection", got.Class)
	}
	if got.Class.Vulnerable() {
		t.Error("body echo must not count as a vulnerability")
	}
}

// The genuine article: the first message declares a zero-length body, so
// everything after it is a second message.
func TestSplitBeyondFramingIsCritical(t *testing.T) {
	w := "HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n" +
		resp("200 OK", "Content-Type: text/html", "<html>"+can.Value+"</html>")
	got, ok := Analyze([]byte(w), can)
	if !ok || got.Class != ResponseSplit {
		t.Fatalf("class = %q, ok = %v, want response-splitting", got.Class, ok)
	}
	if got.Severity != Critical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
	if got.Responses != 2 {
		t.Errorf("responses = %d, want 2", got.Responses)
	}
}

// A truncated body must not let an injected response hide behind a
// Content-Length that overruns the bytes actually received.
func TestOverlongContentLengthIsClamped(t *testing.T) {
	w := "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\nshort body with " + can.Value
	got, ok := Analyze([]byte(w), can)
	if !ok {
		t.Fatal("expected a hit")
	}
	if got.Class != BodyReflect {
		t.Errorf("class = %q, want body-reflection", got.Class)
	}
}

func TestChunkedFramingDelimitsTheFirstMessage(t *testing.T) {
	w := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n" +
		resp("200 OK", "", "<html>"+can.Value+"</html>")
	got, ok := Analyze([]byte(w), can)
	if !ok || got.Class != ResponseSplit {
		t.Fatalf("class = %q, ok = %v, want response-splitting after the chunked terminator", got.Class, ok)
	}
}

// Without Content-Length or chunked encoding the body runs to EOF, so there is
// no framing boundary and nothing can be proven to be a second message.
func TestUnframedBodyIsNeverASplit(t *testing.T) {
	w := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
		"<p>HTTP/1.1 200 OK\r\n" + can.Header + ": " + can.Value + "</p>"
	got, _ := Analyze([]byte(w), can)
	if got.Class == ResponseSplit {
		t.Errorf("unframed body reported as a split")
	}
}

func TestFirstMessageEnd(t *testing.T) {
	const empty = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	cases := []struct {
		name string
		wire string
		want int
	}{
		// A zero-length body ends the message exactly at the blank line.
		{"content length zero", empty, len(empty)},
		{"content length counts the body", empty + "xx", len(empty)},
		{"no framing", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody", -1},
		{"no blank line", "HTTP/1.1 200 OK\r\nContent-Length: 0", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			head, bodyStart, framed := headBoundary([]byte(tc.wire))
			got := firstMessageEnd([]byte(tc.wire), headerLines(head), bodyStart, framed)
			if got != tc.want {
				t.Errorf("firstMessageEnd = %d, want %d", got, tc.want)
			}
		})
	}
}
