// Package inject enumerates the places in a request where a payload can be
// placed, and builds the resulting request line.
//
// Placement matters more than payload choice. Real CRLF sinks are usually a
// query parameter that feeds a redirect or a cookie (?next=, ?url=, ?lang=),
// not the end of the path, so a scanner that only appends to the path misses
// most of them.
//
// Requests are built as raw path and query strings rather than through
// url.URL's normalising accessors. The caller assigns them to URL.Opaque and
// URL.RawQuery, which net/http writes to the wire verbatim. That keeps the
// request line exactly as constructed: no re-encoding of the payload, and no
// path cleaning of traversal prefixes.
package inject

import (
	"fmt"
	"net/url"
	"strings"
)

// Kind identifies a class of injection point.
type Kind string

const (
	PathAppend Kind = "path"       // append to the end of the path
	PathSlash  Kind = "path-slash" // append after a trailing slash
	QueryValue Kind = "query"      // append to an existing parameter value
	QueryName  Kind = "query-name" // append to an existing parameter name
	QueryNew   Kind = "new-param"  // add a parameter that did not exist
	BodyValue  Kind = "body"       // append to a form-encoded body value
)

// AllKinds is the default set, ordered by how often each one pays off.
var AllKinds = []Kind{QueryValue, PathAppend, PathSlash, QueryNew, BodyValue, QueryName}

// ParseKinds turns a comma-separated list into a kind set.
func ParseKinds(s string) ([]Kind, error) {
	if strings.TrimSpace(s) == "" {
		return AllKinds, nil
	}
	valid := map[Kind]bool{}
	for _, k := range AllKinds {
		valid[k] = true
	}
	var out []Kind
	for _, f := range strings.Split(s, ",") {
		k := Kind(strings.ToLower(strings.TrimSpace(f)))
		if f == "" {
			continue
		}
		if !valid[k] {
			return nil, fmt.Errorf("unknown sink %q", f)
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return AllKinds, nil
	}
	return out, nil
}

// Point is a single injection point in a specific request.
type Point struct {
	Kind  Kind
	Param string // parameter name, for query and body sinks
	index int    // position in the raw parameter list
}

// String renders the point for reporting, e.g. "query:next".
func (p Point) String() string {
	if p.Param == "" {
		return string(p.Kind)
	}
	return string(p.Kind) + ":" + p.Param
}

// Request is a built request, ready to be put on the wire.
type Request struct {
	Path  string // raw, always begins with "/"
	Query string // raw, without the leading "?"
	Body  string
}

// kv is one raw, still-encoded parameter.
type kv struct {
	name, val string
	hasEq     bool
}

// parseRaw splits a query or form body without decoding anything. url.ParseQuery
// cannot be used here: it decodes values, and re-encoding them would mangle the
// payload and silently drop malformed parameters.
func parseRaw(s string) []kv {
	if s == "" {
		return nil
	}
	var out []kv
	for _, part := range strings.Split(s, "&") {
		if part == "" {
			continue
		}
		if i := strings.Index(part, "="); i >= 0 {
			out = append(out, kv{name: part[:i], val: part[i+1:], hasEq: true})
			continue
		}
		out = append(out, kv{name: part})
	}
	return out
}

func encodeRaw(ps []kv) string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.name)
		if p.hasEq {
			b.WriteByte('=')
			b.WriteString(p.val)
		}
	}
	return b.String()
}

// Points enumerates the injection points available for a URL and body,
// restricted to the requested kinds and ordered by that restriction.
func Points(u *url.URL, body string, kinds []Kind) []Point {
	query := parseRaw(u.RawQuery)
	form := parseRaw(body)

	var out []Point
	for _, k := range kinds {
		switch k {
		case PathAppend, PathSlash, QueryNew:
			out = append(out, Point{Kind: k})
		case QueryValue:
			for i, p := range query {
				out = append(out, Point{Kind: k, Param: p.name, index: i})
			}
		case QueryName:
			for i, p := range query {
				out = append(out, Point{Kind: k, Param: p.name, index: i})
			}
		case BodyValue:
			// Only inject into something that actually looks form-encoded;
			// splicing a payload into JSON or XML would just break the parse.
			if looksFormEncoded(body) {
				for i, p := range form {
					out = append(out, Point{Kind: k, Param: p.name, index: i})
				}
			}
		}
	}
	return out
}

func looksFormEncoded(body string) bool {
	if body == "" {
		return false
	}
	t := strings.TrimSpace(body)
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") || strings.HasPrefix(t, "<") {
		return false
	}
	return strings.Contains(body, "=")
}

// Build applies a payload at a point and returns the resulting request.
//
// Values are appended to whatever is already there rather than replacing it,
// so a parameter the application validates ("next=/home") keeps its valid
// prefix and still reaches the sink.
func Build(u *url.URL, body string, p Point, pay string) Request {
	req := Request{Path: rawPath(u), Query: u.RawQuery, Body: body}

	switch p.Kind {
	case PathAppend:
		req.Path = req.Path + pay
	case PathSlash:
		req.Path = strings.TrimSuffix(req.Path, "/") + "/" + pay
	case QueryNew:
		add := "clrfkd=" + pay
		if req.Query == "" {
			req.Query = add
		} else {
			req.Query = req.Query + "&" + add
		}
	case QueryValue:
		ps := parseRaw(u.RawQuery)
		if p.index < len(ps) {
			ps[p.index].val += pay
			ps[p.index].hasEq = true
			req.Query = encodeRaw(ps)
		}
	case QueryName:
		ps := parseRaw(u.RawQuery)
		if p.index < len(ps) {
			ps[p.index].name += pay
			req.Query = encodeRaw(ps)
		}
	case BodyValue:
		ps := parseRaw(body)
		if p.index < len(ps) {
			ps[p.index].val += pay
			ps[p.index].hasEq = true
			req.Body = encodeRaw(ps)
		}
	}

	if !strings.HasPrefix(req.Path, "/") {
		req.Path = "/" + req.Path
	}
	// A request target starting with "//" reads as a protocol-relative URL;
	// net/http would prepend the scheme and send an absolute-form request.
	for strings.HasPrefix(req.Path, "//") {
		req.Path = req.Path[1:]
	}
	return req
}

// rawPath returns the path as it arrived, without normalisation. EscapedPath
// re-encodes when RawPath is absent, which is correct here: an untouched target
// URL should go out the way the user wrote it.
func rawPath(u *url.URL) string {
	if u.RawPath != "" {
		return u.RawPath
	}
	if u.Path == "" {
		return "/"
	}
	return u.EscapedPath()
}
