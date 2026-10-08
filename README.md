# clrfkd

[![CI](https://github.com/type5afe/clrfkd/actions/workflows/ci.yml/badge.svg)](https://github.com/type5afe/clrfkd/actions/workflows/ci.yml)  [![Go Reference](https://camo.githubusercontent.com/5c4f6d26776a66139c3846cb5161ea768e18d6ac9624c16614dd1cececd0757e/68747470733a2f2f706b672e676f2e6465762f62616467652f6769746875622e636f6d2f74797065356166652f636c72666b642e737667)](https://pkg.go.dev/github.com/type5afe/clrfkd)  [![Go Report Card](https://camo.githubusercontent.com/17fa36e1c7e3655d368d979f1b0870b4f29bf40265a9ffc8d50bed6bef02e713/68747470733a2f2f676f7265706f7274636172642e636f6d2f62616467652f6769746875622e636f6d2f74797065356166652f636c72666b64)](https://goreportcard.com/report/github.com/type5afe/clrfkd)  [![Latest release](https://camo.githubusercontent.com/3485873af2cabe6744063a254d1a6efd296d7628dc43ccd3e67ab1868e0d55ac/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f762f72656c656173652f74797065356166652f636c72666b643f736f72743d73656d766572)](https://github.com/type5afe/clrfkd/releases/latest)  [![Go version](https://camo.githubusercontent.com/6d20371caa3002b4f44d46ae477dfbd6138df1b04d493f70ea824aa06932db28/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f676f2d6d6f642f676f2d76657273696f6e2f74797065356166652f636c72666b64)](https://github.com/type5afe/clrfkd/blob/072b86784f80d4b97b6b4fcf2ef4656f449f2f47/go.mod)  [![Dependencies](https://camo.githubusercontent.com/2e7335ac36e73e3008de51759b29de1f8155bdb7ade828067bd6536471d6b0c8/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f646570656e64656e636965732d6e6f6e652d627269676874677265656e)](https://github.com/type5afe/clrfkd/blob/072b86784f80d4b97b6b4fcf2ef4656f449f2f47/go.mod)  [![License](https://camo.githubusercontent.com/b8cadaa967891081f8f165695470689986c028821dd8a040132f6e661795dc0d/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f6c6963656e73652d4d49542d626c7565)](https://github.com/type5afe/clrfkd/blob/072b86784f80d4b97b6b4fcf2ef4656f449f2f47/LICENSE)

clrfkd - CRLF injection scanner. Finds header injection, HTTP response splitting and
`Set-Cookie` injection.

```
$ clrfkd -u 'https://target.tld/redirect?next=/home'
[HIGH] https://target.tld/redirect?next=/home%0d%0aX-Clrfkd-4fba1aa3%3a%20e161b9861016 (header-injection)
    sink=query:next payload=pct/crlf/none status=302 confidence=confirmed
    evidence: X-Clrfkd-4fba1aa3: e161b9861016
```

- Injects into every query value, parameter name, path, body value and a new
  parameter. Not just the end of the URL.
- Reads raw socket bytes, so a split response is detected instead of being
  discarded by the HTTP client along with the rest of the message.
- Tells injection apart from reflection. An echoed payload is not a finding.
- Random per-run canary, and every finding is re-sent and confirmed.
- Dead hosts cost one request. Scans stop at the first confirmed hit.
- Streams stdin, collapses near-duplicate URLs, rate limits, speaks JSON Lines.
- Zero dependencies.

## Install

```sh
go install github.com/type5afe/clrfkd/cmd/clrfkd@latest
```

Prebuilt binaries for linux, macOS and windows are on the
[releases page](https://github.com/type5afe/clrfkd/releases/latest).

From a clone: `make build` (to `./bin/clrfkd`), `make test`, `make install`.
Go 1.24 or newer.

## Usage

```sh
clrfkd -u 'https://target.tld/redirect?next=/home'
gau target.tld | clrfkd -c 20 --rate 50
clrfkd -l urls.txt -x http://127.0.0.1:8080 --json -o findings.jsonl
clrfkd -u https://target.tld/login -X POST -d 'next=/home&user=a'
clrfkd -u 'https://target.tld/r?next=/home' -t 3 --all     # thorough, one endpoint
```

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

Findings on stdout, everything else on stderr.

## Findings

| class | severity | meaning |
|---|---|---|
| `response-splitting` | critical | a second, attacker defined response came back on the connection |
| `header-injection` | high | the canary arrived as its own response header |
| `cookie-injection` | high | the canary arrived inside `Set-Cookie` |
| `header-reflection` | medium | payload reached a header value, CRLF encoded or stripped |
| `body-reflection` | info | payload came back only in the body |

The first three set the exit code. The last two show only under `-v`;
`header-reflection` locates a sink worth a `-t 3` sweep.

`-v` also prints a ready-to-paste repro:

```sh
curl -gsSik --path-as-is -i 'https://target.tld/r?next=/home%0d%0aX-Clrfkd-4fba1aa3%3a%20e161b9861016'
```

## Payload tiers

| tier | payloads | contents |
|---|---|---|
| 1 (default) | 6 | `%0d%0a`, `%0a`, `%0d`, lower and upper case hex |
| 2 | 36 | double encoding, `%e5%98%8d` and `%e5%98%8a`, `%00` and `%3f` prefixes |
| 3 | 175 | triple encoding, overlong UTF-8, obs-fold and tab terminators, traversal |

Tier 1 covers what actually works in the field. Bare LF is in it on purpose:
nginx, Node and Go all accept one as a header terminator, so it lands where a
filtered CRLF pair does not.

A clean target costs 31 requests at tier 1. A vulnerable one is usually found in
under 10.

## JSON output

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

## Lab

`make lab` starts a deliberately vulnerable server on `127.0.0.1:8099`. Never
expose it on a network you do not control.

```sh
clrfkd -u 'http://127.0.0.1:8099/hdr?next=/home'      # header injection
clrfkd -u 'http://127.0.0.1:8099/cookie?next=/home'   # Set-Cookie
clrfkd -u 'http://127.0.0.1:8099/filter?next=/home'   # only a bare LF gets through
clrfkd -u 'http://127.0.0.1:8099/safe?next=/home'     # nothing, correctly
clrfkd -u 'http://127.0.0.1:8099/body?next=/home' -v  # reflection, not a finding
```

## Safety

Only scan what you are authorised to scan.

`--split` writes a complete second HTTP response, which is what proves a
critical finding and also what can poison a shared cache and serve your payload
to real users. It is off by default, and the default probe proves the same
injection without that risk. clrfkd reports critical on its own whenever a split
shows up on the wire.

## Contributing

`make check` is what CI runs: `gofmt`, `go vet`, tests under `-race`. New
payload encodings are the most useful contribution.

## Licence

MIT. See [LICENSE](LICENSE).
