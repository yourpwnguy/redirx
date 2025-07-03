<div align="center">
	<h1> RedirX</h1>
  <h4 align="center">Fastest open redirect vulnerability scanner with intelligent fuzzing and mutation engine.</h4>
  <a href="https://github.com/yourpwnguy/yourpwnguy/issues">
		<img src="https://img.shields.io/github/go-mod/go-version/yourpwnguy/redirx?color=ffb29b&labelColor=1C2325&style=for-the-badge">
	</a>
	<a href="https://github.com/yourpwnguy/yourpwnguy/issues">
		<img src="https://img.shields.io/github/issues/yourpwnguy/redirx?color=ffb29b&labelColor=1C2325&style=for-the-badge">
	</a>
	<a href="https://github.com/yourpwnguy/yourpwnguy/stargazers">
		<img src="https://img.shields.io/github/stars/yourpwnguy/redirx?color=fab387&labelColor=1C2325&style=for-the-badge">
	</a>
	<a href="./LICENSE">
		<img src="https://img.shields.io/github/license/yourpwnguy/redirx?color=FCA2AA&labelColor=1C2325&style=for-the-badge">
	</a>
	<br>
</div>

---

## ⚡ Features

* High-speed scanning (10,000+ mutations/min) for open redirect detection.
* URL mutation engine to fuzz redirect parameters.
* Match response status codes (`-mc`) and filter vulnerable results only (`-vuln`).
* Built-in concurrency control for optimal performance.
* Color-coded output and real-time counters.

---

## 🛠️ Installation

To install redirx:

```bash
go install -v github.com/yourpwnguy/redirx/cmd/redirx@latest

# Optional: move binary to a system-wide directory
cp ~/go/bin/redirx /usr/local/bin/
```

---

## 📝 Usage

```yaml
Usage:
  redirx [flags]

Flags:
  -h, --help              help for redirx
  -m, --mcode ints        Status Codes to match
  -p, --payloads string   Path to file containing payloads
  -r, --rate int          Max concurrent requests (rate-limit) (default 5)
  -u, --url strings       Url(s) to scan (repeatable)
  -l, --url-list string   Path to file containing urls (one per line)
  -v, --vuln              Show only vulnerable results (BUG) and suppress SAFE lines
```

---

## ❓ Why redirx?

`redirx` is designed with these goal: **to be the fastest in its class and precision**. Unlike bloated scanners, redirx aggressively mutates URL parameters and uses intelligent response validation to reduce noise. Whether you're automating recon pipelines or manually hunting, `redirx` makes testing open redirects fast, accurate, and easy to integrate.

---

## 🤝 Contributions

Open to pull requests, bug reports, and feature suggestions. Got an idea? [Open an issue](https://github.com/yourpwnguy/redirx/issues) or submit a PR.
