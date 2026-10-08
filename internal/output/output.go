// Package output renders findings.
//
// Three shapes, because the tool gets used three ways: read by a person,
// piped into the next tool in a chain, or archived for triage. The human and
// silent forms go to stdout; progress, errors and the summary go to stderr, so
// that a pipeline never has to filter decoration out of its input.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/type5afe/clrfkd/internal/engine"
)

// Mode selects a rendering.
type Mode int

const (
	Human  Mode = iota // coloured, one line per finding plus evidence
	Silent             // vulnerable URLs only
	JSON               // one JSON object per line
)

// Writer renders findings to a stream, and optionally to a file as well.
type Writer struct {
	mu      sync.Mutex
	out     io.Writer
	errOut  io.Writer
	file    io.WriteCloser
	mode    Mode
	color   bool
	verbose bool

	start    time.Time
	targets  int
	requests int
	errors   int
	bySev    map[string]int
}

// Options configures a Writer.
type Options struct {
	Mode    Mode
	Color   bool
	Verbose bool
	File    io.WriteCloser
}

// New builds a Writer.
func New(opt Options) *Writer {
	return &Writer{
		out:     os.Stdout,
		errOut:  os.Stderr,
		file:    opt.File,
		mode:    opt.Mode,
		color:   opt.Color,
		verbose: opt.Verbose,
		start:   time.Now(),
		bySev:   map[string]int{},
	}
}

// ANSI colours, applied only when the destination is a terminal.
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
)

func (w *Writer) c(code, s string) string {
	if !w.color {
		return s
	}
	return code + s + reset
}

func (w *Writer) sevColor(sev string) string {
	switch sev {
	case "critical":
		return magenta
	case "high":
		return red
	case "medium":
		return yellow
	default:
		return blue
	}
}

// Result records one target's outcome and prints whatever it warrants.
func (w *Writer) Result(r engine.Result) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.targets++
	w.requests += r.Requests
	if r.Err != nil {
		w.errors++
		if w.verbose {
			fmt.Fprintf(w.errOut, "%s %s %s\n",
				w.c(dim, "[err]"), r.Target, w.c(dim, r.Err.Error()))
		}
		return
	}
	for _, f := range r.Findings {
		w.bySev[f.Severity]++
		w.finding(f)
	}
}

func (w *Writer) finding(f engine.Finding) {
	switch w.mode {
	case JSON:
		b, err := json.Marshal(f)
		if err != nil {
			return
		}
		w.emit(string(b) + "\n")
	case Silent:
		if f.Vulnerable() {
			w.emit(f.URL + "\n")
		}
	default:
		sev := strings.ToUpper(f.Severity)
		line := fmt.Sprintf("%s %s %s\n",
			w.c(bold+w.sevColor(f.Severity), "["+sev+"]"),
			w.c(w.sevColor(f.Severity), f.URL),
			w.c(dim, "("+f.Class+")"),
		)
		var b strings.Builder
		b.WriteString(line)
		b.WriteString(fmt.Sprintf("    sink=%s payload=%s status=%d confidence=%s\n",
			w.c(cyan, f.Sink), w.c(cyan, f.PayloadID), f.Status, f.Confidence))
		if f.Evidence != "" {
			b.WriteString("    " + w.c(dim, "evidence: "+oneLine(f.Evidence)) + "\n")
		}
		if w.verbose {
			b.WriteString("    " + w.c(dim, f.Curl) + "\n")
		}
		w.emit(b.String())
	}
}

// emit writes to stdout and, when one is configured, to the output file. The
// file always receives the machine-readable or plain form without colour.
func (w *Writer) emit(s string) {
	fmt.Fprint(w.out, s)
	if w.file != nil {
		if w.mode == Human {
			fmt.Fprint(w.file, stripANSI(s))
			return
		}
		fmt.Fprint(w.file, s)
	}
}

// Infof writes progress to stderr, where it cannot pollute a pipe.
func (w *Writer) Infof(format string, args ...any) {
	if w.mode == Silent && !w.verbose {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintf(w.errOut, "%s %s\n", w.c(dim, "[*]"), fmt.Sprintf(format, args...))
}

// Summary prints the closing counts to stderr.
func (w *Writer) Summary() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.mode == Silent && !w.verbose {
		return
	}
	vuln := w.bySev["critical"] + w.bySev["high"]
	fmt.Fprintf(w.errOut, "\n%s %d targets, %d requests, %d findings (%d critical, %d high, %d medium, %d info), %d errors in %s\n",
		w.c(dim, "[*]"),
		w.targets, w.requests, vuln+w.bySev["medium"]+w.bySev["info"],
		w.bySev["critical"], w.bySev["high"], w.bySev["medium"], w.bySev["info"],
		w.errors, time.Since(w.start).Truncate(time.Millisecond),
	)
}

// Findings reports the number of vulnerable findings, for the exit code.
func (w *Writer) Findings() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bySev["critical"] + w.bySev["high"]
}

// Close releases the output file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 180 {
		s = s[:180] + "..."
	}
	return s
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
