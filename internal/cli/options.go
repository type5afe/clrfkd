// Package cli parses and validates command line options.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/type5afe/clrfkd/internal/inject"
	"github.com/type5afe/clrfkd/internal/output"
)

// Version is overridden at build time with -ldflags "-X ...cli.Version=vX.Y.Z".
var Version = "dev"

// headerList collects repeated -H flags.
type headerList []string

func (h *headerList) String() string     { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

// Options is the parsed configuration.
type Options struct {
	URL, List string
	Method    string
	Data      string
	Headers   headerList
	Cookie    string
	UserAgent string
	Proxy     string
	Timeout   time.Duration
	Retries   int
	Follow    bool
	TLSVerify bool

	Tier        int
	Sinks       string
	Split       bool
	All         bool
	Verify      bool
	Dedupe      bool
	Concurrency int
	Probes      int
	Rate        float64
	Delay       time.Duration

	Output  string
	JSON    bool
	Silent  bool
	Verbose bool
	NoColor bool
	ShowVer bool

	// Derived
	Input      io.Reader
	Kinds      []inject.Kind
	HTTPHeader http.Header
	OutFile    io.WriteCloser
	Mode       output.Mode
	Color      bool
	ColorErr   bool
}

const usage = `clrfkd - CRLF injection scanner

Usage:
  clrfkd -u <url> [options]
  clrfkd -l <file> [options]
  cat urls.txt | clrfkd [options]

Input:
  -u, --url <URL>          single target (scheme optional, defaults to https)
  -l, --list <FILE>        file of targets, one per line (# comments allowed)
                           reads stdin when it is a pipe

Request:
  -X, --method <METHOD>    HTTP method (default GET)
  -d, --data <DATA>        request body; form-encoded bodies are injected too
  -H, --header <K: V>      extra request header, repeatable
  -b, --cookie <COOKIE>    Cookie header value
  -A, --user-agent <UA>    User-Agent header
  -x, --proxy <URL>        proxy, e.g. http://127.0.0.1:8080
      --timeout <DUR>      per-request timeout (default 10s)
      --retries <N>        retries on network error or 429/5xx (default 1)
      --follow             follow redirects (default off, redirects are evidence)
      --tls-verify         verify TLS certificates (default off, for proxying)

Scan:
  -t, --tier <1|2|3>       payload set (default 1)
                           1 standard encodings, finds nearly everything real
                           2 adds filter-bypass encodings
                           3 adds exotic encodings, for a known sink
      --sinks <LIST>       restrict injection points, comma separated, from:
                           query,path,path-slash,new-param,body,query-name
      --split              also send full response-splitting payloads
                           WARNING: writes a whole fake response, which can
                           poison a shared cache. Use only where permitted.
      --all                report every working payload, not just the first
      --no-verify          skip the confirmation request (faster, noisier)
      --no-dedupe          scan near-duplicate URLs separately

Performance:
  -c, --concurrency <N>    targets scanned in parallel (default 10)
  -p, --probes <N>         probes in flight per target (default 5)
      --rate <N>           global cap in requests/sec, 0 for unlimited
      --delay <DUR>        pause before each probe, e.g. 100ms

Output:
  -o, --output <FILE>      also write results to a file
      --json               JSON Lines on stdout, one object per finding
  -s, --silent             print only vulnerable URLs
  -v, --verbose            include reflections, errors and curl commands
      --no-color           disable colour
  -V, --version            print version
  -h, --help               this text

Exit status:
  0  completed, nothing found
  1  error
  2  completed, vulnerabilities found
`

// Parse reads the command line and validates it.
func Parse(args []string) (*Options, error) {
	o := &Options{}
	fs := flag.NewFlagSet("clrfkd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	str := func(p *string, def string, names ...string) {
		for _, n := range names {
			fs.StringVar(p, n, def, "")
		}
	}
	bl := func(p *bool, def bool, names ...string) {
		for _, n := range names {
			fs.BoolVar(p, n, def, "")
		}
	}
	it := func(p *int, def int, names ...string) {
		for _, n := range names {
			fs.IntVar(p, n, def, "")
		}
	}
	dur := func(p *time.Duration, def time.Duration, names ...string) {
		for _, n := range names {
			fs.DurationVar(p, n, def, "")
		}
	}

	str(&o.URL, "", "u", "url")
	str(&o.List, "", "l", "list")
	str(&o.Method, http.MethodGet, "X", "method")
	str(&o.Data, "", "d", "data")
	str(&o.Cookie, "", "b", "cookie")
	str(&o.UserAgent, "", "A", "user-agent")
	str(&o.Proxy, "", "x", "proxy")
	str(&o.Sinks, "", "sinks")
	str(&o.Output, "", "o", "output")
	dur(&o.Timeout, 10*time.Second, "timeout")
	dur(&o.Delay, 0, "delay")
	it(&o.Retries, 1, "retries")
	it(&o.Tier, 1, "t", "tier")
	it(&o.Concurrency, 10, "c", "concurrency")
	it(&o.Probes, 5, "p", "probes")
	bl(&o.Follow, false, "follow")
	bl(&o.TLSVerify, false, "tls-verify")
	bl(&o.Split, false, "split")
	bl(&o.All, false, "all")
	bl(&o.JSON, false, "json")
	bl(&o.Silent, false, "s", "silent")
	bl(&o.Verbose, false, "v", "verbose")
	bl(&o.NoColor, false, "no-color")
	bl(&o.ShowVer, false, "V", "version")
	fs.Var(&o.Headers, "H", "")
	fs.Var(&o.Headers, "header", "")
	fs.Float64Var(&o.Rate, "rate", 0, "")

	noVerify := fs.Bool("no-verify", false, "")
	noDedupe := fs.Bool("no-dedupe", false, "")
	help := false
	bl(&help, false, "h", "help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, ErrHelp
		}
		return nil, fmt.Errorf("%w\n\nrun 'clrfkd -h' for usage", err)
	}
	if help {
		return nil, ErrHelp
	}
	if o.ShowVer {
		return o, nil
	}

	o.Verify = !*noVerify
	o.Dedupe = !*noDedupe

	if o.Tier < 1 || o.Tier > 3 {
		return nil, fmt.Errorf("--tier must be 1, 2 or 3")
	}
	if o.Concurrency < 1 {
		return nil, fmt.Errorf("--concurrency must be at least 1")
	}
	if o.Probes < 1 {
		return nil, fmt.Errorf("--probes must be at least 1")
	}
	if o.Retries < 0 {
		return nil, fmt.Errorf("--retries cannot be negative")
	}
	if o.Timeout <= 0 {
		return nil, fmt.Errorf("--timeout must be positive")
	}

	kinds, err := inject.ParseKinds(o.Sinks)
	if err != nil {
		return nil, err
	}
	o.Kinds = kinds

	// Input: an explicit flag wins, otherwise a piped stdin.
	switch {
	case o.URL != "":
		o.Input = strings.NewReader(o.URL)
	case o.List != "":
		f, err := os.Open(o.List)
		if err != nil {
			return nil, fmt.Errorf("opening target list: %w", err)
		}
		o.Input = f
	case isPipe(os.Stdin):
		o.Input = os.Stdin
	default:
		return nil, ErrNoTarget
	}

	o.HTTPHeader = http.Header{}
	for _, h := range o.Headers {
		i := strings.Index(h, ":")
		if i <= 0 {
			return nil, fmt.Errorf("malformed header %q, want 'Name: value'", h)
		}
		o.HTTPHeader.Add(strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]))
	}
	if o.Cookie != "" {
		o.HTTPHeader.Set("Cookie", o.Cookie)
	}
	if o.UserAgent != "" {
		o.HTTPHeader.Set("User-Agent", o.UserAgent)
	}

	if o.Output != "" {
		f, err := os.OpenFile(o.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("opening output file: %w", err)
		}
		o.OutFile = f
	}

	switch {
	case o.JSON:
		o.Mode = output.JSON
	case o.Silent:
		o.Mode = output.Silent
	default:
		o.Mode = output.Human
	}
	noColor := o.NoColor || os.Getenv("NO_COLOR") != ""
	o.Color = !noColor && isTerminal(os.Stdout)
	o.ColorErr = !noColor && isTerminal(os.Stderr)

	return o, nil
}

// ErrHelp signals that usage was requested.
var ErrHelp = errors.New("help requested")

// ErrNoTarget signals that nothing was given to scan. A bare invocation is a
// request to be told how to use the tool, not a mistake worth a terse error.
var ErrNoTarget = errors.New("no target: pass -u, -l, or pipe a list to stdin")

// ColorStderr reports whether stderr should carry ANSI colour. It takes the
// raw arguments because it is needed on the path where parsing failed and
// there are no parsed options to consult.
func ColorStderr(args []string) bool {
	for _, a := range args {
		if a == "--no-color" || a == "-no-color" {
			return false
		}
	}
	return os.Getenv("NO_COLOR") == "" && isTerminal(os.Stderr)
}

// Usage returns the help text.
func Usage() string { return usage }

// isPipe reports whether stdin has been redirected, covering both a pipe
// ("gau t.com | clrfkd") and a file redirection ("clrfkd < urls.txt").
func isPipe(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice == 0
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
