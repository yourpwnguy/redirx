<div align="center">

# RedirX

**open redirect scanner with a mutation engine**

[![CI](https://github.com/yourpwnguy/redirx/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/yourpwnguy/redirx/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/yourpwnguy/redirx?style=flat-square)](https://github.com/yourpwnguy/redirx/releases)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](./LICENSE)

</div>

So here's the thing. I wanted an open redirect scanner that just works, doesn't drown me in false positives, and tells me exactly where in the redirect chain things went sideways. Couldn't find one I liked, so I wrote this.

You feed it URLs. It swaps every query parameter with a bunch of redirect payloads, follows the hops, and checks two things before it screams "vuln":

1. did we land on a different domain than we started on?
2. can that landing be traced back to the payload we injected?

That second check matters a lot. Tons of sites bounce every request through their CDN or SSO no matter what you put in the params. Naive scanners flag all of that. This one doesn't.

## What you get

- 37 curated bypass payloads: scheme-relative, userinfo confusion, backslash tricks, tab injection, dot-segment traversal, double encoding, all that good stuff
- A live counter at the bottom of your terminal with speed and ETA, ffuf style
- Per-hop chain capture with real status codes, so you see exactly which hop escaped
- Payload influence checking to kill CDN/SSO false positives
- Optional baseline mode that learns where the target legitimately redirects before firing payloads
- IP redirect classification (internal vs loopback vs external) since that doubles as an SSRF hint
- JSON lines output for piping into other tools
- Proxy support for Burp/mitmproxy
- Clean piped output. Zero escape codes when stdout isn't a terminal

## Install

Grab a binary from [releases](https://github.com/yourpwnguy/redirx/releases). Linux, macOS and Windows builds are there, plus deb, rpm and Arch packages if you're into that.

Or the Go way:

```bash
go install github.com/yourpwnguy/redirx/cmd/redirx@latest
```

Or clone and build it yourself:

```bash
git clone https://github.com/yourpwnguy/redirx && cd redirx
make build
```

## Usage

The short version:

```bash
redirx -u "https://victim.com/login?next=dashboard"
```

Some more ways to run it:

```bash
redirx -l urls.txt                          # file full of targets
cat recon-urls.txt | redirx -c 50 -v        # pipe it, crank concurrency, vulns only
redirx -l urls.txt --baseline               # control requests first, fewer FPs
redirx -l urls.txt -j -o results.json       # JSON lines to a file
redirx -l urls.txt --proxy http://127.0.0.1:8080   # through Burp
redirx -l urls.txt -H "Cookie: session=xyz" # authenticated scanning
```

## All the flags

| Flag | Short | Default | What it does |
|------|-------|---------|--------------|
| `--url` | `-u` | | URL(s) to scan, repeatable |
| `--url-list` | `-l` | | File with one URL per line |
| `--payloads` | `-p` | | Custom payload file, one per line |
| `--concurrency` | `-c` | `5` | Max parallel probes |
| `--timeout` | `-t` | `10` | Request timeout in seconds |
| `--max-redirects` | | `10` | Hop cap per probe |
| `--method` | `-X` | `HEAD` | HTTP method |
| `--proxy` | | | Proxy URL |
| `--header` | `-H` | | Extra headers, repeatable |
| `--vuln-only` | `-v` | | Findings only, hide SAFE/ERR |
| `--baseline` | | | Control requests to filter legit bounces |
| `--output` | `-o` | | Output file path |
| `--json` | `-j` | | JSON lines output |
| `--quiet` | `-q` | | No banner, no counter |

## How detection actually works

1. Collect URLs from flags, a file, or stdin
2. Generate mutations: every param times every payload
3. Fire each mutation through a worker pool, following redirects and recording every hop
4. Compare the landing domain against the original domain using proper eTLD+1 matching (so sub.example.co.uk counts as example.co.uk)
5. Run the influence gate: only report a finding if the landing traces back to our payload
6. If baseline mode is on, drop anything that matches a known legit bounce
7. Report VULN / SAFE / ERR

Errors are never reported as safe. DNS fail, TLS error, timeout? That's ERR, counted separately. A security tool that says "nothing happened" when it couldn't even connect is lying to you.

## Payload categories

| Category | Examples |
|----------|----------|
| Scheme-relative | `//google.com`, `///google.com` |
| Userinfo confusion | `//example.com@google.com` |
| Backslash variants | `%5c`, `\\` |
| Tab/CRLF injection | `%09`, `%0d%0a` |
| Dot-segment traversal | `%2f..`, `%2e%2e` |
| Double encoding | `%252f`, `%252e%252e` |
| Protocol manipulation | `/https:`, `/https:/` |
| Path confusion | `/./`, `//\;@` |

Got your own list? Load it with `-p mypayloads.txt`.

## Project layout

```
cmd/redirx                 entry point, three lines
cmd/cli                    cobra command, flags, help screen, version stamping

internal/config            scan configuration struct
internal/payload           built-in payload set plus file loader
internal/httpclient        HTTP client with per-hop chain capture

internal/detector          the brain: mutation, probing, verdicts,
                           domain extraction, influence gate, baselines

internal/output            console writer (live counter, colors), JSON writer
internal/scanner           composition root: worker pool, channels, lifecycle
```

There's a longer writeup in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) if you want the full picture including why the terminal renderer works the way it does.

## Development

```bash
make check              # fmt + vet + lint + race tests + cross build, same as CI
make test-race          # tests under the race detector
make cover              # HTML coverage report
make release-snapshot   # dry run of the whole release pipeline into dist/
```

Releases are tag driven. Push a tag and CI does the rest:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

## License

MIT
