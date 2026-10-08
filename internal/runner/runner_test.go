package runner

import (
	"testing"
)

// Lists harvested from archives are mostly the same few endpoints with
// different identifiers. Collapsing them on shape is usually the largest
// single reduction in requests for a real run, because every one of those URLs
// offers exactly the same injection surface.
func TestShapeCollapsesNearDuplicates(t *testing.T) {
	groups := [][]string{
		{
			"https://t.com/user?id=1",
			"https://t.com/user?id=2",
			"https://t.com/user?id=99999",
		},
		{
			"https://t.com/u/1234/edit",
			"https://t.com/u/5678/edit",
		},
		{
			"https://t.com/p?a=1&b=2",
			"https://t.com/p?b=9&a=8", // parameter order is irrelevant
		},
		{
			"https://T.COM/x?q=1",
			"https://t.com/x?q=2", // host case is irrelevant
		},
	}
	for i, g := range groups {
		first := Shape(g[0])
		for _, u := range g[1:] {
			if got := Shape(u); got != first {
				t.Errorf("group %d: %q and %q have different shapes (%q vs %q)",
					i, g[0], u, first, got)
			}
		}
	}
}

// Collapsing must not go so far that it hides a distinct injection surface.
func TestShapeKeepsDistinctSurfacesApart(t *testing.T) {
	distinct := []string{
		"https://t.com/user?id=1",
		"https://t.com/user?name=1",   // different parameter name
		"https://t.com/user",          // no parameters
		"https://t.com/admin?id=1",    // different path
		"http://t.com/user?id=1",      // different scheme
		"https://other.com/user?id=1", // different host
		"https://t.com/user?id=1&x=2", // extra parameter
	}
	seen := map[string]string{}
	for _, u := range distinct {
		s := Shape(u)
		if prev, ok := seen[s]; ok {
			t.Errorf("%q and %q collapsed to the same shape %q", prev, u, s)
		}
		seen[s] = u
	}
}

func TestIsVariable(t *testing.T) {
	for _, s := range []string{"1", "1234", "0", "deadbeef1", "550e8400-e29b-41d4-a716-446655440000"} {
		if !isVariable(s) {
			t.Errorf("isVariable(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "edit", "user", "admin", "api", "v1", "settings", "abcdef"} {
		if isVariable(s) {
			t.Errorf("isVariable(%q) = true, want false", s)
		}
	}
}

// An unparseable line must still be distinguishable, not silently merged with
// every other unparseable line.
func TestShapeFallsBackToRawInput(t *testing.T) {
	if Shape("ftp://x/y") == Shape("ftp://a/b") {
		t.Error("unparseable targets collapsed together")
	}
}
