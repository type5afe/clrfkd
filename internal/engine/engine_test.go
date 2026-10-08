package engine

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/type5afe/clrfkd/internal/httpx"
	"github.com/type5afe/clrfkd/internal/payload"
)

// vulnLab is a deliberately vulnerable HTTP server written at the socket level.
// It has to be: net/http refuses to write a header value containing CR or LF,
// which is precisely the bug being reproduced, so a realistic target cannot be
// built on top of it.
//
// Behaviour is chosen by the first path segment:
//
//	/hdr   copies the tainted value into a Location header verbatim, the
//	       classic unvalidated-redirect sink
//	/safe  the same, with CR and LF stripped first
//	/body  echoes the tainted value into the response body only
//	/plain a fixed, clean response
//
// The tainted value is the "next" query parameter when one is present and the
// path otherwise, which is how a real application behaves: it reads one named
// parameter rather than the whole request target. A scanner therefore has to
// place its payload in the right parameter to reach the sink.
func vulnLab(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				first, err := br.ReadString('\n')
				if err != nil {
					return
				}
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}

				parts := strings.Fields(first)
				if len(parts) < 2 {
					return
				}
				target := parts[1]
				mode := "plain"
				switch {
				case strings.HasPrefix(target, "/hdr"):
					mode = "hdr"
				case strings.HasPrefix(target, "/safe"):
					mode = "safe"
				case strings.HasPrefix(target, "/body"):
					mode = "body"
				}
				value := taintedValue(target)

				switch mode {
				case "hdr":
					io.WriteString(c, "HTTP/1.1 302 Found\r\nLocation: "+value+
						"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				case "safe":
					clean := strings.NewReplacer("\r", "", "\n", "").Replace(value)
					io.WriteString(c, "HTTP/1.1 302 Found\r\nLocation: "+clean+
						"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				case "body":
					body := "<p>not found: " + value + "</p>"
					io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: "+
						itoa(len(body))+"\r\nConnection: close\r\n\r\n"+body)
				default:
					io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				}
			}(c)
		}
	}()
	return "http://" + ln.Addr().String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// taintedValue returns the attacker-controlled string this fake application
// trusts: the "next" query parameter if it has one, otherwise the path.
func taintedValue(target string) string {
	path, query := target, ""
	if i := strings.Index(target, "?"); i >= 0 {
		path, query = target[:i], target[i+1:]
	}
	for _, pair := range strings.Split(query, "&") {
		if name, val, ok := strings.Cut(pair, "="); ok && name == "next" {
			return decodeOnce(val)
		}
	}
	return decodeOnce(path)
}

// decodeOnce is a lenient single-pass percent decoder, matching the behaviour
// of a sloppy application: malformed escapes are passed through rather than
// rejected.
func decodeOnce(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func newEngine(t *testing.T, cfg Config) (*Engine, payload.Canary) {
	t.Helper()
	c, err := httpx.New(httpx.Config{Timeout: 3 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	can, err := payload.NewCanary()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodGet
	}
	return New(cfg, c, can), can
}

func TestDetectsHeaderInjectionInQueryValue(t *testing.T) {
	base := vulnLab(t)
	// One probe at a time, so the sink ordering is deterministic and this also
	// asserts that query values are tried before the path and new parameters.
	eng, _ := newEngine(t, Config{Tier: 1, Verify: true, ProbeConc: 1})

	res := eng.Scan(context.Background(), base+"/hdr?next=/home")
	if res.Err != nil {
		t.Fatalf("scan error: %v", res.Err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("no finding against a vulnerable query sink")
	}
	f := res.Findings[0]
	if f.Class != "header-injection" {
		t.Errorf("class = %q, want header-injection", f.Class)
	}
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Confidence != "confirmed" {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if f.Sink != "query:next" {
		t.Errorf("sink = %q, want query:next tried first", f.Sink)
	}
	if f.Curl == "" {
		t.Error("finding carries no reproduction command")
	}
}

// Early exit is the request-economy claim: a vulnerable target must not be
// swept with the whole payload set after the first confirmed hit.
func TestEarlyExitStopsAfterFirstConfirmedFinding(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 3, Verify: true, ProbeConc: 1})

	res := eng.Scan(context.Background(), base+"/hdr?next=/home")
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding")
	}
	full := len(eng.Payloads())
	if res.Requests >= full {
		t.Errorf("spent %d requests with a %d-payload set; early exit did not fire",
			res.Requests, full)
	}
}

func TestAllFlagEnumeratesEveryWorkingPayload(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 1, Verify: false, All: true, ProbeConc: 4})

	res := eng.Scan(context.Background(), base+"/hdr?next=/home")
	if len(res.Findings) < 2 {
		t.Fatalf("--all reported %d findings, want several", len(res.Findings))
	}
}

func TestFilteringTargetIsNotReportedAsVulnerable(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 3, Verify: true, ProbeConc: 4})

	res := eng.Scan(context.Background(), base+"/safe?next=/home")
	for _, f := range res.Findings {
		if f.Vulnerable() {
			t.Errorf("false positive on a filtering target: %s via %s", f.Class, f.PayloadID)
		}
	}
}

// A target that echoes the payload into its body is reflecting, not splitting.
// Calling that a vulnerability is the most common way a scanner wastes a
// reader's time, so it must be classified as informational.
func TestBodyEchoIsReflectionNotVulnerability(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 1, Verify: true, ProbeConc: 4, ReportInfo: true})

	res := eng.Scan(context.Background(), base+"/body?next=/home")
	if len(res.Findings) == 0 {
		t.Skip("no reflection observed")
	}
	for _, f := range res.Findings {
		if f.Vulnerable() {
			t.Errorf("body echo reported as %s, want an informational class", f.Class)
		}
		if f.Class != "body-reflection" {
			t.Errorf("class = %q, want body-reflection", f.Class)
		}
	}
}

func TestCleanTargetYieldsNothing(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 2, Verify: true, ProbeConc: 4})

	res := eng.Scan(context.Background(), base+"/plain?a=1")
	if len(res.Findings) != 0 {
		t.Errorf("clean target produced %d findings: %+v", len(res.Findings), res.Findings)
	}
}

// A dead host must cost one request, not the whole payload set. On an archive
// list full of dead hosts this is where most of the saving comes from.
func TestDeadHostCostsOneRequest(t *testing.T) {
	eng, _ := newEngine(t, Config{Tier: 3, Verify: true, ProbeConc: 4})

	// Port 1 on loopback refuses connections immediately.
	res := eng.Scan(context.Background(), "http://127.0.0.1:1/x?a=1")
	if res.Err == nil {
		t.Fatal("expected a baseline error")
	}
	if res.Requests != 1 {
		t.Errorf("spent %d requests on a dead host, want 1", res.Requests)
	}
	if len(res.Findings) != 0 {
		t.Errorf("dead host produced findings: %+v", res.Findings)
	}
}

func TestResponseSplittingIsClassifiedCritical(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 1, Split: true, Verify: true, ProbeConc: 1, All: true})

	res := eng.Scan(context.Background(), base+"/hdr?next=/home")
	var got bool
	for _, f := range res.Findings {
		if f.Class == "response-splitting" {
			got = true
			if f.Severity != "critical" {
				t.Errorf("severity = %q, want critical", f.Severity)
			}
			if f.Responses < 2 {
				t.Errorf("responses on wire = %d, want at least 2", f.Responses)
			}
		}
	}
	if !got {
		t.Error("split payloads did not produce a response-splitting finding")
	}
}

func TestPathSinkIsProbed(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 1, Verify: true, ProbeConc: 4})

	// No query at all, so only the path sinks can fire.
	res := eng.Scan(context.Background(), base+"/hdr")
	if len(res.Findings) == 0 {
		t.Fatal("path sink not detected")
	}
	if !strings.HasPrefix(res.Findings[0].Sink, "path") &&
		res.Findings[0].Sink != "new-param" {
		t.Errorf("sink = %q, want a path or new-param sink", res.Findings[0].Sink)
	}
}

func TestContextCancellationStopsScan(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 3, Verify: true, ProbeConc: 2})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := eng.Scan(ctx, base+"/plain?a=1")
	if res.Requests > 1 {
		t.Errorf("cancelled scan still sent %d requests", res.Requests)
	}
}

func TestNormalizeRejectsJunkAndDefaultsScheme(t *testing.T) {
	if u, err := Normalize("example.com/x"); err != nil || u.Scheme != "https" {
		t.Errorf("bare host: got %v, %v; want https scheme", u, err)
	}
	for _, bad := range []string{"", "   ", "ftp://x.com", "javascript:alert(1)", "https://"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) accepted an invalid target", bad)
		}
	}
}

// Without --all a target yields exactly one finding, however many payloads
// happen to work and however many probes were in flight when the first hit
// landed.
func TestDefaultReportsOneFindingPerTarget(t *testing.T) {
	base := vulnLab(t)
	for _, probes := range []int{1, 5, 16} {
		eng, _ := newEngine(t, Config{Tier: 2, Verify: true, ProbeConc: probes})
		res := eng.Scan(context.Background(), base+"/hdr?next=/home")
		if len(res.Findings) != 1 {
			t.Errorf("probes=%d: got %d findings, want exactly 1", probes, len(res.Findings))
		}
		if len(res.Findings) == 1 && res.Findings[0].Confidence != "confirmed" {
			t.Errorf("probes=%d: confidence = %q, want confirmed", probes, res.Findings[0].Confidence)
		}
	}
}

// Concurrent hits must not each spend a confirmation request.
func TestConcurrentHitsConfirmOnlyOnce(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 1, Verify: true, ProbeConc: 6})
	res := eng.Scan(context.Background(), base+"/hdr?next=/home")
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	// Baseline, the probes already in flight when the first hit landed, and
	// exactly one confirmation. The bound is two rounds of probes rather than
	// one because the feeder can dispatch another batch before the first
	// worker's verdict is visible.
	if max := 1 + 2*6 + 1; res.Requests > max {
		t.Errorf("spent %d requests, want at most %d", res.Requests, max)
	}
}

// Reflections repeat for every payload tried, so they are collapsed per class
// and sink rather than printed dozens of times.
func TestInformationalFindingsAreCollapsed(t *testing.T) {
	base := vulnLab(t)
	eng, _ := newEngine(t, Config{Tier: 2, Verify: true, ProbeConc: 4, ReportInfo: true, All: true})
	res := eng.Scan(context.Background(), base+"/body?next=/home")
	seen := map[string]bool{}
	for _, f := range res.Findings {
		k := f.Class + "|" + f.Sink
		if seen[k] {
			t.Errorf("duplicate informational finding for %s", k)
		}
		seen[k] = true
	}
}
