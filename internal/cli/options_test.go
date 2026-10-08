package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/type5afe/clrfkd/internal/inject"
	"github.com/type5afe/clrfkd/internal/output"
)

// Binding one of a short and long flag pair to the wrong field is easy to do
// and silent when it happens: a body that overwrote the HTTP method would
// never be sent, and nothing would complain. These assertions keep each flag
// attached to its own field.
func TestDataFlagSetsBodyAndNotMethod(t *testing.T) {
	for _, name := range []string{"-d", "--data"} {
		o, err := Parse([]string{"-u", "https://t.com", name, "a=1&b=2"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if o.Data != "a=1&b=2" {
			t.Errorf("%s: Data = %q, want the body", name, o.Data)
		}
		if o.Method != "GET" {
			t.Errorf("%s: Method = %q, want the GET default to survive", name, o.Method)
		}
	}
}

func TestEveryFlagHasShortAndLongForm(t *testing.T) {
	pairs := []struct {
		short, long, value string
		check              func(*Options) string
	}{
		{"-X", "--method", "POST", func(o *Options) string { return o.Method }},
		{"-b", "--cookie", "sid=1", func(o *Options) string { return o.Cookie }},
		{"-A", "--user-agent", "ua/1", func(o *Options) string { return o.UserAgent }},
		{"-x", "--proxy", "http://127.0.0.1:8080", func(o *Options) string { return o.Proxy }},
	}
	for _, p := range pairs {
		for _, form := range []string{p.short, p.long} {
			o, err := Parse([]string{"-u", "https://t.com", form, p.value})
			if err != nil {
				t.Fatalf("%s: %v", form, err)
			}
			if got := p.check(o); got != p.value {
				t.Errorf("%s: got %q, want %q", form, got, p.value)
			}
		}
	}
}

func TestDefaults(t *testing.T) {
	o, err := Parse([]string{"-u", "https://t.com"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Tier != 1 {
		t.Errorf("Tier = %d, want 1", o.Tier)
	}
	if !o.Verify {
		t.Error("verification should be on by default")
	}
	if !o.Dedupe {
		t.Error("de-duplication should be on by default")
	}
	if o.Split {
		t.Error("response-splitting payloads must be opt-in")
	}
	if o.Follow {
		t.Error("redirects should not be followed by default; they are evidence")
	}
	if o.Mode != output.Human {
		t.Error("default output mode should be human readable")
	}
	if len(o.Kinds) != len(inject.AllKinds) {
		t.Errorf("Kinds = %v, want all sinks", o.Kinds)
	}
}

func TestNegatingFlags(t *testing.T) {
	o, err := Parse([]string{"-u", "https://t.com", "--no-verify", "--no-dedupe"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Verify {
		t.Error("--no-verify ignored")
	}
	if o.Dedupe {
		t.Error("--no-dedupe ignored")
	}
}

func TestRepeatedHeadersAccumulate(t *testing.T) {
	o, err := Parse([]string{"-u", "https://t.com", "-H", "A: 1", "-H", "B: 2", "--header", "C: 3"})
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"A": "1", "B": "2", "C": "3"} {
		if got := o.HTTPHeader.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
}

func TestCookieAndUserAgentBecomeHeaders(t *testing.T) {
	o, err := Parse([]string{"-u", "https://t.com", "-b", "sid=abc", "-A", "scanner/1"})
	if err != nil {
		t.Fatal(err)
	}
	if o.HTTPHeader.Get("Cookie") != "sid=abc" {
		t.Errorf("Cookie = %q", o.HTTPHeader.Get("Cookie"))
	}
	if o.HTTPHeader.Get("User-Agent") != "scanner/1" {
		t.Errorf("User-Agent = %q", o.HTTPHeader.Get("User-Agent"))
	}
}

func TestInvalidInputIsRejected(t *testing.T) {
	cases := map[string][]string{
		"no target":        {"-t", "1"},
		"tier too low":     {"-u", "https://t.com", "-t", "0"},
		"tier too high":    {"-u", "https://t.com", "-t", "4"},
		"zero concurrency": {"-u", "https://t.com", "-c", "0"},
		"zero probes":      {"-u", "https://t.com", "-p", "0"},
		"negative retries": {"-u", "https://t.com", "--retries", "-1"},
		"zero timeout":     {"-u", "https://t.com", "--timeout", "0s"},
		"unknown sink":     {"-u", "https://t.com", "--sinks", "nope"},
		"malformed header": {"-u", "https://t.com", "-H", "novalue"},
		"missing list":     {"-l", "/nonexistent/path/to/list.txt"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(args); err == nil {
				t.Errorf("Parse(%v) accepted invalid input", args)
			}
		})
	}
}

func TestHelpIsSignalled(t *testing.T) {
	for _, f := range []string{"-h", "--help"} {
		if _, err := Parse([]string{f}); !errors.Is(err, ErrHelp) {
			t.Errorf("%s: err = %v, want ErrHelp", f, err)
		}
	}
	if !strings.Contains(Usage(), "clrfkd") {
		t.Error("usage text is empty or wrong")
	}
}

func TestSinksRestriction(t *testing.T) {
	o, err := Parse([]string{"-u", "https://t.com", "--sinks", "query,body"})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Kinds) != 2 || o.Kinds[0] != inject.QueryValue || o.Kinds[1] != inject.BodyValue {
		t.Errorf("Kinds = %v", o.Kinds)
	}
}

func TestOutputModes(t *testing.T) {
	for _, tc := range []struct {
		flag string
		want output.Mode
	}{
		{"--json", output.JSON},
		{"-s", output.Silent},
	} {
		o, err := Parse([]string{"-u", "https://t.com", tc.flag})
		if err != nil {
			t.Fatal(err)
		}
		if o.Mode != tc.want {
			t.Errorf("%s: mode = %v, want %v", tc.flag, o.Mode, tc.want)
		}
	}
}

func TestURLInputIsReadable(t *testing.T) {
	o, err := Parse([]string{"-u", "https://t.com/x?a=1"})
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, _ := o.Input.Read(b)
	if string(b[:n]) != "https://t.com/x?a=1" {
		t.Errorf("input = %q", string(b[:n]))
	}
}

// The banner must stay out of stdout and out of machine-readable modes, or it
// ends up in whatever the scan is piped into.
func TestBannerIsSuppressedForMachineReaders(t *testing.T) {
	for _, flag := range []string{"--json", "-s"} {
		o, err := Parse([]string{"-u", "https://t.com", flag})
		if err != nil {
			t.Fatal(err)
		}
		if o.Mode == output.Human {
			t.Errorf("%s: mode is still Human, so the banner would print", flag)
		}
	}
	o, err := Parse([]string{"-u", "https://t.com"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Mode != output.Human {
		t.Error("default mode should be Human so the banner prints")
	}
}

func TestBannerContent(t *testing.T) {
	var b strings.Builder
	Banner(&b, false)
	got := b.String()
	if !strings.Contains(got, "CRLF injection scanner") {
		t.Error("banner omits the tagline")
	}
	if !strings.Contains(got, Version) {
		t.Errorf("banner omits the version %q", Version)
	}
	if strings.Contains(got, "\033[") {
		t.Error("colour emitted when it was not requested")
	}
	var c strings.Builder
	Banner(&c, true)
	if !strings.Contains(c.String(), "\033[") {
		t.Error("colour requested but not emitted")
	}
}

// A bare invocation has to be distinguishable from a bad flag, so that the
// caller can answer it with the banner and usage instead of a terse error.
func TestBareInvocationIsReportedAsNoTarget(t *testing.T) {
	_, err := Parse([]string{"--tier", "1"})
	if !errors.Is(err, ErrNoTarget) {
		t.Fatalf("err = %v, want ErrNoTarget", err)
	}
	// A genuine mistake must not be mistaken for it.
	_, err = Parse([]string{"-u", "https://t.com", "--tier", "9"})
	if errors.Is(err, ErrNoTarget) || err == nil {
		t.Fatalf("a bad flag gave err = %v", err)
	}
}

func TestColorStderrHonoursNoColorFlag(t *testing.T) {
	if ColorStderr([]string{"--no-color"}) {
		t.Error("--no-color ignored on the parse-failure path")
	}
}
