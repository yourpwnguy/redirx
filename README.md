<div align="center">

# RedirX

**Open redirect vulnerability scanner with mutation engine**

[![CI](https://github.com/yourpwnguy/redirx/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/yourpwnguy/redirx/actions/workflows/ci.yml)
[![Release](https://github.com/yourpwnguy/redirx/actions/workflows/release.yml/badge.svg?style=flat-square)](https://github.com/yourpwnguy/redirx/releases)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](./LICENSE)
[![Report a vulnerability](https://img.shields.io/badge/report-vulnerability-red?style=flat-square)](./SECURITY.md)

</div>

---

RedirX detects open-redirect vulnerabilities by mutating URL query parameters with a curated payload list, following redirect chains, and comparing landing domains against the target's registrable domain (eTLD+1). Includes optional baseline control requests to reduce false positives from legitimate SSO/auth/geo-redirects.

## Features

- **Mutation engine** — 42 curated bypass payloads covering scheme-relative, userinfo confusion, backslash variants, tab/CRLF tricks, dot-segment traversal, and double-encoded forms
- **Bounded worker pool** — fixed goroutine pool with configurable concurrency; no unbounded fan-out
- **HTTP timeouts** — configurable per-request timeout, max redirects, and context cancellation (Ctrl-C)
- **Baseline control** — optional `--baseline` mode sends an unmodified request first and subtracts legitimate bounce domains from findings
- **Per-hop redirect chain capture** — records every intermediate redirect hop, not just the final URL
- **JSON output** — machine-readable JSON lines for pipeline integration (`-j -o results.json`)
- **Proxy support** — route through Burp, mitmproxy, or any HTTP proxy (`--proxy`)
- **Custom headers** — inject auth tokens, cookies, or custom headers (`-H "Authorization: Bearer ..."`)
- **Configurable method** — HEAD (default, fast), GET, or any HTTP method (`-X GET`)
- **TTY-aware output** — clean piped output, no escape sequences in non-TTY mode
- **Vuln-only mode** — suppress SAFE lines, show only findings (`-v`)
- **Zero false-positive baseline** — when `--baseline` is used, domains the target normally redirects to are excluded

## Installation

**Release binaries** (recommended) — grab the archive or native package for your platform from [Releases](https://github.com/yourpwnguy/redirx/releases):

```bash
# linux/macOS example — latest release, this shell:
curl -sSL https://github.com/yourpwnguy/redirx/releases/latest/download/redirx_$(curl -s https://api.github.com/repos/yourpwnguy/redirx/releases/latest | grep -oP '"tag_name": "\K[^"]+')_linux_amd64.tar.gz | tar xz redirx && sudo mv redirx /usr/local/bin/
```

**Native packages** — `.deb` / `.rpm` / Arch packages ship with every release.

**From source** (requires Go 1.24+):

```bash
go install github.com/yourpwnguy/redirx/cmd/redirx@latest
```

Or clone and use the Makefile:

```bash
git clone https://github.com/yourpwnguy/redirx
cd redirx
go build -o redirx ./cmd/redirx
```

## Usage

```bash
# Scan a single URL
redirx -u "https://victim.com/login?next=dashboard"

# Scan multiple URLs
redirx -u "https://a.com/?redir=x" -u "https://b.com/?goto=y"

# Scan from a file
redirx -l urls.txt

# Pipe from stdin
cat urls.txt | redirx

# With baseline control (recommended for production)
redirx -l urls.txt --baseline

# JSON output to file
redirx -l urls.txt -j -o results.json

# Through Burp proxy
redirx -l urls.txt --proxy http://127.0.0.1:8080

# Custom headers (auth scanning)
redirx -l urls.txt -H "Cookie: session=abc123" -H "Authorization: Bearer token"

# Use GET instead of HEAD
redirx -l urls.txt -X GET

# Show only vulnerabilities
redirx -l urls.txt -v
```

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--url` | `-u` | | URL(s) to scan (repeatable) |
| `--url-list` | `-l` | | File containing URLs, one per line |
| `--payloads` | `-p` | | Custom payloads file (one per line) |
| `--concurrency` | `-c` | `5` | Max concurrent requests |
| `--timeout` | `-t` | `10` | HTTP timeout in seconds |
| `--max-redirects` | | `10` | Max redirects to follow |
| `--method` | `-X` | `HEAD` | HTTP method |
| `--proxy` | | | HTTP proxy URL |
| `--header` | `-H` | | Custom headers (`Key: Value`) |
| `--vuln-only` | `-v` | `false` | Show only vulnerable results |
| `--baseline` | | `false` | Run control requests to reduce false positives |
| `--output` | `-o` | | Output file path |
| `--json` | `-j` | `false` | Output as JSON lines |
| `--quiet` | `-q` | `false` | Suppress banner and UI |
| `--help` | `-h` | | Help |

## Architecture

```
cmd/redirx/main.go                    Entry point
cmd/cli/root.go                       Cobra CLI, flag parsing, stdin fallback
cmd/cli/stdin.go                      Stdin/TTY detection and line reading

internal/config/config.go             Configuration struct
internal/payload/payloads.go          Built-in 42-payload list + file loader
internal/httpclient/client.go         HTTP client with timeout, proxy, redirect chain capture

internal/detector/extract.go          eTLD+1 domain extraction via publicsuffix
internal/detector/mutate.go           URL mutation engine (param x payload)
internal/detector/baseline.go         Control request to establish baseline domains
internal/detector/detect.go           Core detection: follow, classify, verdict

internal/output/result.go             Result struct (detection engine → display layer)
internal/output/console.go            Human-readable colored output
internal/output/json.go               JSON lines output
internal/output/ui.go                 Live terminal status bar with coalesced ticker
internal/output/writer.go             Writer interface (pluggable output)

internal/scanner/scan.go              Orchestration: collect, baseline, worker pool, summary
internal/scanner/collect.go           URL/file collection with dedup
```

### Design decisions

- **Result struct on channel** — detection emits `output.Result`, not pre-formatted strings. Output layer formats it. Detection never touches display. Adding CSV/console/Slack output requires zero changes to detection logic.
- **Worker pool** — `N` goroutines consume from a buffered jobs channel. No per-URL goroutine spawn. Bounded memory, bounded TCP connections, clean shutdown.
- **Context propagation** — every HTTP request uses `http.NewRequestWithContext`. Ctrl-C cancels in-flight requests via `signal.NotifyContext`.
- **Baseline control** — when `--baseline` is enabled, one unmutated request is sent per URL before mutations begin. Landing domains from that control request are excluded from vulnerability classification. This eliminates false positives from legitimate auth gates, SSO, geo-redirects, and bot checks.
- **Error != SAFE** — network errors, DNS failures, and TLS errors are counted and reported as ERR, never as SAFE. Silent failure is a security defect in a security tool.

## Testing

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run specific package tests
go test ./internal/detector/ -v
go test ./internal/httpclient/ -v
```

Tests cover:
- `internal/detector/extract_test.go` — eTLD+1 extraction, IP handling, edge cases
- `internal/detector/mutate_test.go` — mutation engine, param preservation, duplicates
- `internal/detector/detect_test.go` — detection logic with httptest servers
- `internal/httpclient/client_test.go` — redirect chains, timeouts, context cancellation
- `internal/output/console_test.go` — output formatting, counts, vuln-only mode
- `internal/payload/payloads_test.go` — payload loading, file parsing

## How detection works

1. **Collect** URLs from `-u`, `-l`, or stdin
2. **Normalize** — bare hostnames get `http://` prepended
3. **Baseline** (optional) — send each URL unmodified, record where it lands
4. **Mutate** — for each URL, generate `(param × payload)` mutations
5. **Probe** — follow redirects for each mutation, capture the full chain
6. **Classify** — compare landing domain (eTLD+1) against original domain
7. **Filter** — exclude baseline bounces when `--baseline` is active
8. **Report** — emit as VULN/SAFE/ERR to console or JSON

## Payload categories

The default payload list covers these open-redirect bypass techniques:

| Category | Example payloads |
|----------|-----------------|
| Scheme-relative | `//google.com`, `///google.com` |
| Userinfo confusion | `//example.com@google.com` |
| Backslash variants | `%5c`, `\\` |
| Tab/CRLF injection | `%09`, `%0d%0a` |
| Dot-segment traversal | `%2f..`, `%2e%2e` |
| Double encoding | `%252f`, `%252e%252e` |
| Protocol manipulation | `/https:`, `/https:/` |
| Path confusion | `/./`, `//\;@` |

Custom payloads can be loaded with `-p payloads.txt`.

## Development

```bash
make help          # list every target
make check         # the exact gate CI runs: fmt + vet + lint + race tests + cross-build
make build         # ./redirx with version stamped from git
make test-race     # unit tests under the race detector
make cover         # HTML coverage report
make release-snapshot   # full GoReleaser pipeline into dist/ (no upload)
```

Cutting a release is tag-driven — GoReleaser builds linux/darwin/windows
(amd64+arm64), packages deb/rpm/arch, generates checksums and a changelog,
and publishes to GitHub Releases automatically:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture invariants and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it all works.

## License

MIT
