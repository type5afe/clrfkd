# clrfkd

**CRLF injection scanner for HTTP.** Finds header injection, HTTP response
splitting and `Set-Cookie` injection, confirms every finding before reporting
it, and hands you the `curl` command that reproduces it.

[![CI](https://github.com/type5afe/clrfkd/actions/workflows/ci.yml/badge.svg)](https://github.com/type5afe/clrfkd/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/type5afe/clrfkd.svg)](https://pkg.go.dev/github.com/type5afe/clrfkd)
[![Go Report Card](https://goreportcard.com/badge/github.com/type5afe/clrfkd)](https://goreportcard.com/report/github.com/type5afe/clrfkd)
[![Latest release](https://img.shields.io/github/v/release/type5afe/clrfkd?sort=semver)](https://github.com/type5afe/clrfkd/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/type5afe/clrfkd)](go.mod)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

CRLF injection happens when a web application copies attacker controlled text
into an HTTP response header without stripping carriage returns and line feeds.
A payload that survives the trip ends a header early and starts a new one. That
gets you an injected header, an injected cookie, or, if you can terminate the
whole message, a second response of your own design, which is the basis for web
cache poisoning and stored XSS.

```
$ clrfkd -u 'https://target.tld/redirect?next=/home'
[*] tier 1, 6 payloads, canary X-Clrfkd-4fba1aa3, sinks [query path path-slash new-param body query-name]
[HIGH] https://target.tld/redirect?next=/home%0d%0aX-Clrfkd-4fba1aa3%3a%20e161b9861016 (header-injection)
    sink=query:next payload=pct/crlf/none status=302 confidence=confirmed
    evidence: X-Clrfkd-4fba1aa3: e161b9861016

[*] 1 targets, 8 requests, 1 findings (0 critical, 1 high, 0 medium, 0 info), 0 errors in 141ms
```

## Contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [What it finds](#what-it-finds)
- [How it works](#how-it-works)
- [Payload tiers](#payload-tiers)
- [Request cost](#request-cost)
- [Safety](#safety)
- [Options](#options)
- [JSON output](#json-output)
- [Exit status](#exit-status)
- [The lab](#the-lab)
- [Contributing](#contributing)

## Features

- **Injects where the sinks are.** Every query parameter value, parameter names,
  the path, a parameter that did not previously exist, and form encoded body
  values. Not just the end of the URL.
- **Sees response splitting.** Reads the raw bytes off the socket, so an
  injected second response is detected instead of being discarded by the HTTP
  client.
- **Separates injection from reflection.** An application that echoes your
  payload into a page is not vulnerable, and is not reported as though it were.
- **Confirms before reporting.** Random per run canary plus a confirmation
  request, so findings are not cache artefacts or one off variance.
- **Cheap.** A baseline request drops dead hosts for one request, probes run in
  likelihood order, and a scan stops at the first confirmed finding.
- **Built for pipelines.** Reads stdin, streams huge lists, JSON Lines output,
  rate limiting, proxy support, meaningful exit codes.
- **Zero third party dependencies.** Standard library only.

## Install

```sh
go install github.com/type5afe/clrfkd/cmd/clrfkd@latest
```

Or from a clone:

```sh
make build      # ./bin/clrfkd
make test       # unit and end to end tests
make install    # into $GOPATH/bin
```

Go 1.24 or newer. Nothing else: a security scanner is a bad place to inherit
someone else's supply chain.

## Quick start

```sh
# one target
clrfkd -u 'https://target.tld/redirect?next=/home'

# a list, piped from your recon tooling
gau target.tld | clrfkd
katana -u target.tld -silent | clrfkd -c 20 --rate 50

# through Burp, as JSON, saving everything
clrfkd -l urls.txt -x http://127.0.0.1:8080 --json -o findings.jsonl

# POST, with the body injected too
clrfkd -u https://target.tld/login -X POST -d 'next=/home&user=a'

# a thorough sweep of one endpoint you believe has a sink
clrfkd -u 'https://target.tld/r?next=/home' -t 3 --all
```

## What it finds

| class | severity | meaning |
|---|---|---|
| `response-splitting` | critical | a second, attacker defined response came back on the connection. Enables web cache poisoning and XSS |
| `header-injection` | high | the canary arrived as its own response header |
| `cookie-injection` | high | the canary arrived inside `Set-Cookie`, which can overwrite session state |
| `header-reflection` | medium | the payload reached a header value but its CRLF was encoded or stripped |
| `body-reflection` | info | the payload came back only in the response body |

The first three are vulnerabilities and set the exit code. The last two are
observations about where the payload landed, and appear only under `-v`.

`header-reflection` is still worth reading. It means the payload reached a
header sink and only the encoding failed, which is exactly when a tier 2 or
tier 3 sweep of that one endpoint is worth the requests.

## How it works

### It injects where the sinks are

Real CRLF sinks are usually a query parameter that feeds a redirect or a cookie
(`?next=`, `?url=`, `?lang=`, `?redirect=`), not the end of the path. Appending
a payload to the end of a URL string only ever reaches one place: if the target
already carries a query, the payload lands inside the **last** parameter's
value, and nothing else is ever tested. A URL carrying a fragment is worse,
because a payload appended after a `#` sits in the fragment and is never
transmitted at all.

clrfkd parses the target and enumerates its injection points, then tries each
one. Payloads are appended to the existing value rather than replacing it, so a
parameter the application validates (`next=/home`) keeps a valid prefix and
still reaches the sink. Query values are tried first, because that is where the
bug usually is, so the first request is the one most likely to land.

The request target is written to the wire byte for byte. No re-encoding of the
payload, and no path cleaning of traversal prefixes.

### It can see the severe case

This is the part that needs a different client design.

When a payload terminates the response and writes a second one, the first
response's framing (a `Content-Length: 0`, say) tells the HTTP client that the
message is over, so everything after it is discarded before any handler sees
it. A scanner built on a parsed response object cannot observe the single most
severe outcome of the bug it is looking for:

```
response on the wire:
  HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n
  HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 18\r\n\r\n<html>CANARY</html>

what a parsed response reports:  status=302, headers={Location, Content-Length}, body=""
canary in headers? no.  canary in body? no.
```

clrfkd tees the connection, so it keeps the raw bytes alongside the parsed
response. A canary inside a second message is reported as `response-splitting`
at critical severity.

HTTP/2 is disabled deliberately. CRLF injection is a property of HTTP/1.x
framing, and in HTTP/2 headers are length prefixed binary fields that a stray
CR cannot terminate, so negotiating h2 would quietly make targets look safe.

### It separates injection from reflection

Reading raw bytes also makes the distinction that keeps the output trustworthy.
If the canary comes back as a header line of its own, the CRLF was honoured and
that is an injection. If it comes back only inside somebody else's header value
or in the response body, the application is echoing the payload rather than
splitting on it, which is an unvalidated redirect or an error page that prints
the URL, not this bug.

The same care applies to splitting itself. A payload that writes
`HTTP/1.1 200 OK` into a page that echoes it back produces something that looks
exactly like a split response. Only bytes beyond where the first message's own
framing ends can be a second message, so that is what gets checked, rather than
simply counting status lines.

### Findings are proven

The canary is random per run, both the header name and its value, so a target
cannot emit it by coincidence and a response cached from an unrelated scan
cannot be mistaken for a hit.

Anything that looks positive is re-sent once and has to produce the same verdict
before it is reported as `confirmed`. One extra request removes the false
positives that come from caches, from one host in a pool differing from its
peers, and from a response that simply varied that run. `--no-verify` skips it.

Every finding carries the sink, the payload id, the status, the matched header
line, and a command that reproduces it:

```sh
curl -gsSik --path-as-is -i 'https://target.tld/r?next=/home%0d%0aX-Clrfkd-4fba1aa3%3a%20e161b9861016'
```

`-g` stops curl treating brackets as globs and `--path-as-is` stops it
collapsing the traversal sequences some payloads use.

### It does not waste requests

- One baseline request first. If the host does not answer, the target is dropped
  without spending a single probe on it. On a list harvested from an archive,
  where many hosts are long dead, this is most of the saving.
- Probes run in likelihood order and the scan stops at the first confirmed
  finding, reported once. `--all` enumerates every working payload when you want
  the full picture.
- Near duplicate targets are collapsed before scanning. Archive output is mostly
  the same endpoints with different identifiers, and `/user?id=1` and
  `/user?id=2` offer the same injection surface, so one of them covers both.
  Usually the single biggest reduction in a real run. `--no-dedupe` turns it off.
- Input is streamed, so a multi million line list costs memory proportional to
  the work in flight rather than to the file.
- `--rate` caps requests per second globally and `--delay` spaces out probes, so
  hammering a target is a choice rather than the default.
- `--retries` backs off on `429` and `5xx` instead of recording a miss.
- `Ctrl-C` cancels work in flight and still prints the summary, so a long run
  cut short does not lose what it found.

## Payload tiers

Coverage is traded against request count explicitly.

| tier | payloads | contents |
|---|---|---|
| 1 (default) | 6 | `%0d%0a`, `%0a`, `%0d`, each in lower and upper case hex |
| 2 | 36 | adds double encoding, the `%e5%98%8d` and `%e5%98%8a` CJK trick, and `%00` and `%3f` prefixes |
| 3 | 175 | adds triple encoding, overlong UTF-8, obs-fold and tab terminators, traversal prefixes |

Tier 1 is the default because plain `%0d%0a` and a bare `%0a` are what actually
work in the field. The higher tiers are filter bypass sweeps, worth spending on
an endpoint you already believe has a sink.

A bare LF is in tier 1 on purpose. nginx, Node and Go all accept one as a header
terminator, so LF only injection succeeds against targets that filter the full
pair.

## Request cost

Measured against the bundled lab, which takes its tainted value from the `next`
query parameter when one is present and the path otherwise, because that is how
a real application behaves: it reads one named parameter, not the whole request
target.

| lab target | what it is | requests | result |
|---|---|---|---|
| `/hdr?next=/home` | sink is the only parameter | 3 | 1 high |
| `/hdr?next=/home&id=1` | sink is not the last parameter | 3 | 1 high |
| `/hdr?next=/home#frag` | URL carries a fragment | 3 | 1 high |
| `/filter?next=/home` | strips `\r\n`, lets a bare `\n` through | 8 | 1 high |
| `/cookie?next=/home` | terminates a `Set-Cookie` header | 3 | 1 high |
| `/safe?next=/home` | strips CR and LF properly | 31 | nothing, correctly |
| `/plain?a=1` | clean endpoint | 31 | nothing |
| `/body?next=/home` | echoes the payload into the body | 31 | nothing, reflection under `-v` |

Three requests is the floor and it means the first probe landed: one baseline,
one payload, one confirmation. Eight on `/filter` is the full tier 1 set at the
first sink plus the bare LF payload that gets through.

Those counts were taken with `-p 1`, which makes them deterministic. The default
`-p 5` runs five probes per target at once, so on a vulnerable target it
finishes sooner in wall clock terms but spends a few more requests, being the
probes already in flight when the first hit lands. Measured over seven runs that
was 4 to 10 requests for `/hdr` and 10 to 27 for `/filter`. Counts for targets
with nothing to find are unaffected and exact: 31 requests every time, being one
baseline plus six tier 1 payloads across five injection points.

## Safety

**Only scan what you are authorised to scan.** This tool sends deliberately
malformed requests.

`--split` is opt in and off by default. Those payloads write a complete second
HTTP response rather than a single header, which is what proves a critical
finding, and is also what can poison a shared cache and serve your injected
response to other users. Use it only where you have permission to, and prefer
the default single header probe for a first pass: it proves the same injection,
and clrfkd reports critical severity on its own whenever a split actually
appears on the wire.

The defaults are chosen to be unsurprising rather than aggressive. Redirects are
not followed, because a `Location` header is evidence. One finding is reported
per target. Nothing is sent to a host that failed its baseline request. The
default User-Agent names the tool, so whoever owns the host you are testing can
identify the traffic in their logs.

## Options

```
Input:
  -u, --url <URL>          single target (scheme optional, defaults to https)
  -l, --list <FILE>        file of targets, one per line (# comments allowed)
                           reads stdin when it is a pipe or redirect

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
      --sinks <LIST>       restrict injection points, comma separated, from:
                           query,path,path-slash,new-param,body,query-name
      --split              also send full response-splitting payloads
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
```

Findings go to stdout. Progress, errors and the summary go to stderr, so a
pipeline never has to filter decoration out of its input.

## JSON output

`--json` emits one object per finding:

```json
{
  "time": "2026-10-08T19:21:04Z",
  "target": "https://target.tld/redirect?next=/home",
  "url": "https://target.tld/redirect?next=/home%0d%0aX-Clrfkd-4fba1aa3%3a%20e161b9861016",
  "method": "GET",
  "sink": "query:next",
  "payload_id": "pct/crlf/none",
  "payload": "%0d%0aX-Clrfkd-4fba1aa3%3a%20e161b9861016",
  "class": "header-injection",
  "severity": "high",
  "confidence": "confirmed",
  "status": 302,
  "responses_on_wire": 1,
  "evidence": "X-Clrfkd-4fba1aa3: e161b9861016",
  "curl": "curl -gsSik --path-as-is -i 'https://target.tld/redirect?next=/home%0d%0a...'"
}
```

## Exit status

| code | meaning |
|---|---|
| 0 | completed, nothing found |
| 1 | error |
| 2 | completed, vulnerabilities found |

```sh
clrfkd -l urls.txt --json -o out.jsonl; [ $? -eq 2 ] && echo "findings in out.jsonl"
```

## The lab

Every claim above is reproducible against the bundled target:

```sh
make lab                                            # listens on 127.0.0.1:8099
clrfkd -u 'http://127.0.0.1:8099/hdr?next=/home' -v
clrfkd -u 'http://127.0.0.1:8099/filter?next=/home' # only a bare LF gets through
clrfkd -u 'http://127.0.0.1:8099/safe?next=/home'   # nothing, correctly
clrfkd -u 'http://127.0.0.1:8099/body?next=/home' -v  # reflection, not a finding
```

`clrfkd-lab` is written at the socket level on purpose. Go's `net/http` refuses
to write a header value containing CR or LF, which is exactly the defect being
reproduced, so a realistic vulnerable target cannot be built on top of it. It
logs every request it receives, which is how the request counts above were
measured.

Never expose it on a network you do not control.

## Contributing

Issues and pull requests are welcome. `make check` is what CI runs: `gofmt`,
`go vet`, and the full test suite under the race detector.

New payload encodings are the most useful contribution. A payload is only worth
adding if it can actually reach the wire, and the test suite enforces that.

## Licence

MIT. See [LICENSE](LICENSE).

---

**Keywords:** CRLF injection, CRLF injection scanner, HTTP response splitting,
header injection, Set-Cookie injection, response splitting scanner, web cache
poisoning, unvalidated redirect, HTTP header CRLF, security scanner, web
security, bug bounty, bug bounty tool, penetration testing, recon, offensive
security, appsec, Go, golang, CLI.
