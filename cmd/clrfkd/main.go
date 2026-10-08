// Command clrfkd scans HTTP targets for CRLF injection.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/type5afe/clrfkd/internal/cli"
	"github.com/type5afe/clrfkd/internal/engine"
	"github.com/type5afe/clrfkd/internal/httpx"
	"github.com/type5afe/clrfkd/internal/output"
	"github.com/type5afe/clrfkd/internal/payload"
	"github.com/type5afe/clrfkd/internal/runner"
)

// Exit codes. 2 for "found something" lets a pipeline branch on the result
// without parsing output.
const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	opt, err := cli.Parse(os.Args[1:])
	if errors.Is(err, cli.ErrHelp) {
		fmt.Fprint(os.Stderr, cli.Usage())
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "clrfkd: %v\n", err)
		return exitError
	}
	if opt.ShowVer {
		fmt.Println("clrfkd " + cli.Version)
		return exitOK
	}

	// A single target that cannot be parsed is a usage error worth reporting
	// now. Lines in a list stay lenient: a few bad ones are normal and should
	// not fail the run.
	if opt.URL != "" {
		if _, err := engine.Normalize(opt.URL); err != nil {
			fmt.Fprintf(os.Stderr, "clrfkd: %v\n", err)
			return exitError
		}
	}

	canary, err := payload.NewCanary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "clrfkd: %v\n", err)
		return exitError
	}

	limiter := httpx.NewLimiter(opt.Rate)
	defer limiter.Close()

	client, err := httpx.New(httpx.Config{
		Timeout:   opt.Timeout,
		Retries:   opt.Retries,
		Proxy:     opt.Proxy,
		TLSVerify: opt.TLSVerify,
		Follow:    opt.Follow,
	}, limiter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clrfkd: %v\n", err)
		return exitError
	}

	eng := engine.New(engine.Config{
		Method:     opt.Method,
		Body:       opt.Data,
		Headers:    opt.HTTPHeader,
		Tier:       opt.Tier,
		Kinds:      opt.Kinds,
		Split:      opt.Split,
		All:        opt.All,
		Verify:     opt.Verify,
		ProbeConc:  opt.Probes,
		Delay:      opt.Delay,
		ReportInfo: opt.Verbose,
	}, client, canary)

	w := output.New(output.Options{
		Mode:    opt.Mode,
		Color:   opt.Color,
		Verbose: opt.Verbose,
		File:    opt.OutFile,
	})
	defer w.Close()

	// Ctrl-C cancels in-flight work and still prints the summary, so a long run
	// that is cut short does not lose what it already found.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if opt.Mode == output.Human {
		cli.Banner(os.Stderr, opt.ColorErr)
	}

	w.Infof("tier %d, %d payloads, canary %s, sinks %v",
		opt.Tier, len(eng.Payloads()), canary.Header, opt.Kinds)
	if opt.Split {
		w.Infof("response-splitting payloads enabled; these can poison shared caches")
	}

	runner.Run(ctx, eng, opt.Input, w, opt.Concurrency, opt.Dedupe)
	w.Summary()

	if ctx.Err() != nil {
		w.Infof("interrupted")
	}
	if w.Findings() > 0 {
		return exitFindings
	}
	return exitOK
}
