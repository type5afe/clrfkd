// Package detect classifies a raw HTTP response for evidence of CRLF injection.
//
// It works on the bytes read off the socket rather than on a parsed
// http.Response, because the most severe outcome is invisible to a parsed one.
// When a payload splits a response, the first response's framing (a
// Content-Length of 0, say) tells net/http that the message is over, so the
// injected second response is discarded by the client before any handler sees
// it. Reading the wire keeps it.
//
// Working on raw bytes also makes the distinctions that matter for false
// positives:
//
//   - Whether the canary came back as a header line of its own, or merely as
//     text inside somebody else's header value or the body. Only the first is
//     an injection. An application that echoes the request URL into a Location
//     header or an error page is reflecting, not splitting, and reporting that
//     as a vulnerability is the quickest way to lose a reader's trust.
//   - Whether an injected response really is a second message, or just text
//     inside the first one's body. A payload that writes "HTTP/1.1 200 OK" into
//     a page that echoes it back produces something that looks exactly like a
//     split until you check it against the first message's framing. Only bytes
//     beyond where the first message ends can be a second response.
package detect

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/type5afe/clrfkd/internal/payload"
)

// Class is what the response proves.
type Class string

const (
	// ResponseSplit means a second, attacker-defined HTTP response came back
	// on the same connection. Enables cache poisoning and XSS.
	ResponseSplit Class = "response-splitting"
	// HeaderInject means the canary arrived as its own response header.
	HeaderInject Class = "header-injection"
	// CookieInject means the canary arrived inside Set-Cookie, which can
	// overwrite session state.
	CookieInject Class = "cookie-injection"
	// HeaderReflect means the payload reached a header value but its CRLF was
	// encoded or stripped. Not exploitable as sent, but it locates a sink: a
	// different encoding may well get through.
	HeaderReflect Class = "header-reflection"
	// BodyReflect means the payload came back only in the body. Informational.
	BodyReflect Class = "body-reflection"
)

// Severity ranks a class for triage.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Info     Severity = "info"
)

// Severity returns the default severity for a class.
func (c Class) Severity() Severity {
	switch c {
	case ResponseSplit:
		return Critical
	case HeaderInject, CookieInject:
		return High
	case HeaderReflect:
		return Medium
	default:
		return Info
	}
}

// Vulnerable reports whether a class is an actual injection rather than an
// observation about where the payload landed.
func (c Class) Vulnerable() bool {
	switch c {
	case ResponseSplit, HeaderInject, CookieInject:
		return true
	}
	return false
}

// Result describes what was found in a response.
type Result struct {
	Class     Class
	Severity  Severity
	Evidence  string // the header line or excerpt that proves it
	Responses int    // HTTP messages counted on the wire
}

// statusLine matches a response status line at the start of a line. Both CRLF
// and bare-LF framing are accepted because a split induced by an LF-only
// payload produces the latter.
var statusLine = regexp.MustCompile(`(?m)^HTTP/\d\.\d[ \t]+\d{3}`)

// Analyze inspects raw wire bytes for the canary and returns the strongest
// class of evidence present.
func Analyze(wire []byte, c payload.Canary) (Result, bool) {
	if len(wire) == 0 {
		return Result{}, false
	}

	head, bodyStart, framed := headBoundary(wire)
	lines := headerLines(head)
	end := firstMessageEnd(wire, lines, bodyStart, framed)

	res := Result{Responses: 1}

	// Strongest first: a second message, beyond where the first one ended,
	// carrying our canary.
	if end >= 0 && end < len(wire) {
		tail := wire[end:]
		if n := len(statusLine.FindAllIndex(tail, -1)); n > 0 {
			res.Responses += n
			if bytes.Contains(tail, []byte(c.Value)) {
				res.Class = ResponseSplit
				res.Severity = Critical
				res.Evidence = excerpt(tail, 240)
				return res, true
			}
		}
	}

	// The canary as a header name of its own: the payload's CRLF was honoured.
	for _, ln := range lines {
		name, val, ok := splitHeader(ln)
		if !ok {
			continue
		}
		if strings.EqualFold(name, c.Header) && strings.Contains(val, c.Value) {
			res.Class = HeaderInject
			res.Severity = High
			res.Evidence = ln
			return res, true
		}
	}

	// The canary inside Set-Cookie: injected cookie rather than header.
	for _, ln := range lines {
		name, val, ok := splitHeader(ln)
		if !ok {
			continue
		}
		if strings.EqualFold(name, "Set-Cookie") && strings.Contains(val, c.Value) {
			res.Class = CookieInject
			res.Severity = High
			res.Evidence = ln
			return res, true
		}
	}

	// The canary inside some other header's value: a sink, but filtered.
	for _, ln := range lines {
		if strings.Contains(ln, c.Value) || strings.Contains(ln, c.Header) {
			res.Class = HeaderReflect
			res.Severity = Medium
			res.Evidence = ln
			return res, true
		}
	}

	body := wire[min(bodyStart, len(wire)):]
	if end >= 0 && end <= len(wire) && end > bodyStart {
		body = wire[bodyStart:end]
	}
	if bytes.Contains(body, []byte(c.Value)) || bytes.Contains(body, []byte(c.Header)) {
		res.Class = BodyReflect
		res.Severity = Info
		res.Evidence = excerptAround(body, c.Value, 120)
		return res, true
	}

	return res, false
}

// headBoundary splits one response at the blank line that ends its header
// block, accepting CRLF or bare-LF framing. framed is false when no blank line
// was found at all, which means the response was truncated.
func headBoundary(msg []byte) (head []byte, bodyStart int, framed bool) {
	if i := bytes.Index(msg, []byte("\r\n\r\n")); i >= 0 {
		return msg[:i], i + 4, true
	}
	if i := bytes.Index(msg, []byte("\n\n")); i >= 0 {
		return msg[:i], i + 2, true
	}
	return msg, len(msg), false
}

// firstMessageEnd returns the offset at which the first HTTP message ends
// according to its own framing, or -1 when the framing does not delimit it.
//
// This is what separates a real split from a page that merely echoes a payload
// shaped like a response. Text inside the first message's declared body is
// body content however much it looks like HTTP; only bytes past the end of
// that body can be a second message. With no Content-Length and no chunked
// encoding the body runs to EOF, so by definition there is no second message.
func firstMessageEnd(wire []byte, lines []string, bodyStart int, framed bool) int {
	if !framed {
		return -1
	}
	var chunked bool
	for _, ln := range lines {
		name, val, ok := splitHeader(ln)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, "Content-Length"):
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || n < 0 {
				continue
			}
			end := bodyStart + n
			if end > len(wire) {
				return len(wire)
			}
			return end
		case strings.EqualFold(name, "Transfer-Encoding"):
			if strings.Contains(strings.ToLower(val), "chunked") {
				chunked = true
			}
		}
	}
	if chunked {
		if i := bytes.Index(wire[bodyStart:], []byte("0\r\n\r\n")); i >= 0 {
			return bodyStart + i + 5
		}
	}
	return -1
}

// headerLines returns the header lines of a head block, dropping the status
// line. Folded continuation lines are returned as their own entries, which is
// what we want: an obs-fold payload lands on one.
func headerLines(head []byte) []string {
	raw := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	if len(raw) <= 1 {
		return nil
	}
	out := make([]string, 0, len(raw)-1)
	for _, ln := range raw[1:] {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

func splitHeader(line string) (name, val string, ok bool) {
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:i])
	if name == "" || strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	return name, strings.TrimSpace(line[i+1:]), true
}

func excerpt(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}

func excerptAround(b []byte, needle string, n int) string {
	i := bytes.Index(b, []byte(needle))
	if i < 0 {
		return excerpt(b, n)
	}
	start := max(0, i-n/2)
	end := min(len(b), i+len(needle)+n/2)
	return excerpt(b[start:end], n+len(needle))
}
