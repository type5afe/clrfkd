package payload

import (
	"strings"
	"testing"
)

func testCanary() Canary { return Canary{Header: "X-Clrfkd-test", Value: "abc123"} }

// Every payload must consist only of characters that survive a request line.
//
// It is an easy mistake to put a literal "\r\n", or a malformed escape such as
// "%u000a", into a payload list. net/url rejects a URL containing a raw control
// character or a bad percent-escape, so entries like that fail before a request
// is even built and only ever produce an error. A payload that cannot reach the
// wire is not coverage, so the whole set is checked here.
func TestEveryPayloadIsSendable(t *testing.T) {
	for _, tier := range []int{1, 2, 3} {
		for _, split := range []bool{false, true} {
			for _, p := range Set(tier, split, testCanary()) {
				for i := 0; i < len(p.Value); i++ {
					b := p.Value[i]
					if b <= 0x20 || b >= 0x7f {
						t.Errorf("payload %s contains byte %#x at %d, which cannot appear in a request line: %q",
							p.ID, b, i, p.Value)
						break
					}
				}
			}
		}
	}
}

func TestTiersAreCumulativeAndOrdered(t *testing.T) {
	var last int
	for _, tier := range []int{1, 2, 3} {
		set := Set(tier, false, testCanary())
		if len(set) <= last {
			t.Errorf("tier %d has %d payloads, not more than the %d before it", tier, len(set), last)
		}
		last = len(set)

		// Cheapest and most likely first, so an early exit happens early.
		for i := 1; i < len(set); i++ {
			if set[i].Tier < set[i-1].Tier {
				t.Fatalf("tier %d set is not ordered by payload tier at index %d", tier, i)
			}
		}
		for _, p := range set {
			if p.Tier > tier {
				t.Errorf("tier %d set contains a tier %d payload (%s)", tier, p.Tier, p.ID)
			}
		}
	}
}

// Tier 1 is the default, so its size is a user-facing promise about how many
// requests a scan costs.
func TestTierOneStaysSmall(t *testing.T) {
	n := len(Set(1, false, testCanary()))
	if n == 0 || n > 10 {
		t.Errorf("tier 1 has %d payloads, want a small set", n)
	}
}

func TestEveryPayloadCarriesTheCanary(t *testing.T) {
	c := testCanary()
	for _, p := range Set(3, true, c) {
		if !strings.Contains(p.Value, c.Header) || !strings.Contains(p.Value, c.Value) {
			t.Errorf("payload %s omits the canary: %q", p.ID, p.Value)
		}
	}
}

func TestPayloadIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Set(3, true, testCanary()) {
		if seen[p.ID] {
			t.Errorf("duplicate payload ID %q", p.ID)
		}
		seen[p.ID] = true
	}
}

// Split payloads are opt-in because they write a whole fake response, so they
// must never appear unless asked for.
func TestSplitPayloadsAreOptIn(t *testing.T) {
	for _, p := range Set(3, false, testCanary()) {
		if p.Split {
			t.Fatalf("payload %s is a split payload but split was not requested", p.ID)
		}
	}
	var got bool
	for _, p := range Set(1, true, testCanary()) {
		if p.Split {
			got = true
			if !strings.Contains(p.Value, "HTTP/1.1%20200%20OK") {
				t.Errorf("split payload %s does not open a second response: %q", p.ID, p.Value)
			}
		}
	}
	if !got {
		t.Error("split requested but no split payloads generated")
	}
}

// A random canary is what makes a hit unambiguous: a target cannot emit this
// header by chance, and a response cached from someone else's scan cannot be
// mistaken for a finding.
func TestCanaryIsRandomAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := NewCanary()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(c.Header, "X-Clrfkd-") {
			t.Fatalf("header = %q", c.Header)
		}
		if len(c.Value) != 12 {
			t.Fatalf("value %q has length %d, want 12", c.Value, len(c.Value))
		}
		key := c.Header + c.Value
		if seen[key] {
			t.Fatal("canary repeated across runs")
		}
		seen[key] = true
		// Must be header-name safe and request-line safe.
		for _, s := range []string{c.Header, c.Value} {
			for i := 0; i < len(s); i++ {
				b := s[i]
				ok := b == '-' || (b >= '0' && b <= '9') ||
					(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
				if !ok {
					t.Fatalf("canary %q contains unsafe byte %#x", s, b)
				}
			}
		}
	}
}

// Bare LF belongs in tier 1: nginx, Node and Go all accept it as a header
// terminator, so it succeeds where filtered CRLF does not.
func TestTierOneIncludesBareLF(t *testing.T) {
	var got bool
	for _, p := range Set(1, false, testCanary()) {
		if strings.HasSuffix(p.ID, "/lf/none") {
			got = true
		}
	}
	if !got {
		t.Error("tier 1 has no bare-LF payload")
	}
}

// A working split payload proves the more severe bug, so it must be tried
// before the plain payload it subsumes. Otherwise an early-exit scan reports
// high when it could have reported critical.
func TestSplitPayloadsComeFirst(t *testing.T) {
	set := Set(1, true, testCanary())
	for i, p := range set {
		if p.Split {
			continue
		}
		if i == 0 || !set[i-1].Split || set[i-1].ID != p.ID+"/split" {
			t.Fatalf("payload %q at index %d is not preceded by its split variant", p.ID, i)
		}
	}
}
