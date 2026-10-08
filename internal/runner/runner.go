// Package runner feeds targets to the engine.
//
// Input is streamed, never slurped. A list harvested from an archive can run to
// millions of lines, and reading it into one string before splitting it costs
// memory proportional to the file rather than to the work in flight.
//
// Targets are also collapsed before they are scanned. Archive output is mostly
// near-duplicates: the same endpoint with a different id in the query. Those
// all share one injection surface, so scanning every one of them re-tests the
// same code path thousands of times. Collapsing on the shape of a URL rather
// than its values is usually the single biggest saving in a real run.
package runner

import (
	"bufio"
	"context"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/type5afe/clrfkd/internal/engine"
	"github.com/type5afe/clrfkd/internal/output"
)

// Run scans every target read from in, with the given target concurrency, and
// reports results through w. It returns when the input is exhausted or the
// context ends.
func Run(ctx context.Context, eng *engine.Engine, in io.Reader, w *output.Writer, concurrency int, dedupe bool) {
	if concurrency < 1 {
		concurrency = 1
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					return
				}
				w.Result(eng.Scan(ctx, t))
			}
		}()
	}

	seen := map[string]bool{}
	sc := bufio.NewScanner(in)
	// URLs can be long; the default 64 KiB token limit is generous but a
	// truncated line would be scanned as a different target, so raise it.
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

	for sc.Scan() {
		if ctx.Err() != nil {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if dedupe {
			k := Shape(line)
			if seen[k] {
				continue
			}
			seen[k] = true
		}
		select {
		case jobs <- line:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
}

// Shape reduces a URL to its injection surface: scheme, host, path and the set
// of parameter names. Two URLs with the same shape offer the same places to
// inject, so scanning one of them covers both.
func Shape(raw string) string {
	u, err := engine.Normalize(raw)
	if err != nil {
		return raw
	}
	var names []string
	for _, p := range strings.Split(u.RawQuery, "&") {
		if p == "" {
			continue
		}
		if i := strings.Index(p, "="); i >= 0 {
			names = append(names, p[:i])
			continue
		}
		names = append(names, p)
	}
	sort.Strings(names)

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	// Collapse identifier-looking path segments: /user/1234/edit and
	// /user/9876/edit are the same endpoint.
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if isVariable(s) {
			segs[i] = "{}"
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Host) + strings.Join(segs, "/") + "?" + strings.Join(names, "&")
}

// isVariable reports whether a path segment looks like an identifier rather
// than a route name: purely numeric, or a long hex-ish string such as a UUID.
func isVariable(s string) bool {
	if s == "" {
		return false
	}
	digits, hexish := 0, 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			hexish++
		case (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-':
			hexish++
		}
	}
	if digits == len(s) {
		return true
	}
	return hexish == len(s) && len(s) >= 8 && digits > 0
}
