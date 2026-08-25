# RedirX Architecture — v0.1.0

> fr fr documentation of how this whole thing works, no cap 🧢❌
>
> RedirX be mutatin' every query param on your target wit a curated payload
> set, followin' every hop, and snitchin' when the landing domain dips out
> of the target's eTLD+1 AND that escape actually traces back to our input.
> Two-factor vibe check so we don't be flaggin' random CDN bounces like amateurs.

---

## 1. The 30-second version

```
urls in ──► mutate ──► worker pool ──► HTTP probe ──► verdict pipeline ──► pretty lines out
              (param × payload)   (-c goroutines)   (chain capture)    (domain + influence gates)
```

That's it. Everything below is just this, but with the receipts.

---

## 2. Package map — who knows who

Dependency flow is a DAG, zero circular deps, composition root at the top:

```
                    ┌──────────────────────────┐
                    │   cmd/redirx/main.go     │  entrypoint, 3 lines, does NOTHING else
                    └────────────┬─────────────┘
                                 ▼
                    ┌──────────────────────────┐
                    │       cmd/cli            │  cobra shell: flags ▸ Config,
                    │  root.go   stdin.go      │  banner, cargo-core help screen,
                    └────────────┬─────────────┘  signal.NotifyContext (ctrl-c = clean)
                                 │ builds
                                 ▼
                    ┌──────────────────────────┐
                    │     internal/config      │  pure data struct. no behavior.
                    └────────────┬─────────────┘  imports: time. that's it. that's the pkg.
                                 │ consumed by
                                 ▼
        ┌────────────────────────────────────────────────┐
        │                internal/scanner                │  ◄── THE COMPOSITION ROOT
        │   scan.go (Run): wiring, worker pool, chans    │      the only pkg that sees everyone
        │   collect.go (URL gathering + dedup)           │
        └──────┬──────────┬──────────────┬───────────┬───┘
               ▼          ▼              ▼           ▼
        ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐
        │ payload  │ │httpclient│ │  detector  │ │  output  │
        │ Default  │ │ Follow() │ │ mutate.go  │ │ Writer   │
        │ Load()   │ │ chain cap│ │ detect.go  │ │ console  │
        └──────────┘ └────┬─────┘ │ influence  │ │ json     │
                          │       │ extract.go │ │ result   │
                          │       │ baseline   │ └────┬─────┘
                          │       └─────┬──────┘      │ uses
                          └─────────────┴─────────────┘
                          detector ──► httpclient (Follow)
                          output   ──► detector  (Verdict enum only)
                          httpclient ──► nobody. leaf node. chillest pkg.
```

**The rule:** `detector` stays pure logic (no terminals, no colors), `output`
stays pure presentation (no HTTP), and they only shake hands through
`DetectionResult ▸ Result` structs. If you break this, you're cooked.

---

## 3. Scan lifecycle — main goroutine's day

```
scanner.Run(ctx, cfg, writer)
│
├─① collectURLs()            -u flags + -l file + stdin pipe
│                             dedup'd, order preserved (debugging >>> randomness)
│
├─② payloads                 cfg.Payloads or payload.Default (~40 curated bypasses)
│
├─③ httpclient.New()         timeout/proxy/method/max-redirects baked in once
│
├─④ [optional] --baseline    one control req per URL (sequential, it's chill)
│                             └─► baselineDomains{eTLD+1: true} = "legit bounces"
│
├─⑤ origDomains{}            pre-compute eTLD+1 per URL (publicsuffix lookup once,
│                             not per mutation — we're not made of CPU cycles)
│
├─⑥ spawn workers × -c       each: for mu := range jobs { Check() → results }
│
├─⑦ feeder goroutine         Mutate(url, payloads) → jobs chan; closes jobs when done
│                             (separate goroutine so drain never deadlocks, iykyk)
│
├─⑧ closer goroutine         workerWg.Wait() → close(results) — clean shutdown signal
│
├─⑨ StartLiveCounter(total)  totalMuts = len(urls) × len(payloads)
│
├─⑩ for r := range results   THE DRAIN LOOP — single writer, no races, period.
│        writer.Write(r)
│
├─⑪ StopLiveCounter()
└─⑫ WriteSummary(chips)      ✓ 435 targets · 6,401 muts · 1,001.7/s · ...
```

Channels: `jobs` and `results` both buffered @256. Bounded = memory stays
flat no matter how unhinged the URL list gets.

---

## 4. Detection pipeline — inside `detector.Check()`

This is where the W's happen. Every mutated URL goes through all 9 gates:

```
                       MutatedURL {orig, param, payload, mutated}
                                        │
                                        ▼
                        ┌───────────────────────────────┐
                        │  client.Follow(ctx, mutated)  │  httpclient
                        │  · clones http.Client per call│  chain captured via
                        │  · CheckRedirect appends hops │  CheckRedirect closure +
                        │  · hop status = req.Response  │  req.Response.StatusCode
                        │  · FinalStatus = resp.Status  │  (per-hop statuses fr)
                        └───────────────┬───────────────┘
                                        ▼
                        ┌───────────────────────────────┐
              err? ────►│ Gate 1: network failure?      │────► Verdict: ERROR
                        │ Gate 2: Final unparseable?    │────► Verdict: ERROR
                        │        ("we don't know" ≠ safe)│
                        └───────────────┬───────────────┘
                                        ▼
                        ┌───────────────────────────────┐
                        │ Gate 3: DOMAIN CHECK          │
                        │  origDomain ≠ finalDomain ?   │
                        └───────────────┬───────────────┘
                                        ▼
                        ┌───────────────────────────────┐
                        │ Enrichment (parallel-ish):    │
                        │  · ClassifyIP(Final)          │──► IPRedirect: internal/
                        │  · HasCredentials(Final)      │    loopback/external tags
                        │  · AnalyzeChain(chain)        │──► escape@hopN
                        └───────────────┬───────────────┘
                                        ▼
                  ┌─────────────────────────────────────────────┐
                  │ Gate 4: BASELINE FILTER                     │
                  │  finalDomain ∈ baselineDomains ? → not vuln  │  kills SSO/auth FPs
                  └──────────────────────┬──────────────────────┘
                                         ▼
                  ┌─────────────────────────────────────────────┐
                  │ Gate 5: PAYLOAD-INFLUENCE 🔥 (the GOAT)      │
                  │                                             │
                  │ PayloadIdentities(payload):                 │
                  │   percent-decode ×3 → regex host scan →      │
                  │   eTLD+1 normalize (+IPv4 literals)          │
                  │                                             │
                  │ influenced IF:                              │
                  │   ✓ landing domain ∈ payload identities      │
                  │   ✓ OR raw/decoded payload echoed in hops    │
                  │   ✓ fail-open if payload has no identity     │
                  │     (pure traversal `/../..`)                │
                  │                                             │
                  │ WHY: playtika bounces EVERYTHING to their    │
                  │ CDN regardless of input. Domain-check alone  │
                  │ would flag it. This gate said "nah". 💅      │
                  └──────────────────────┬──────────────────────┘
                                         ▼
                     verdict = Vuln iff  influenced
                                       && !baselineBounce
                                       && payloadDriven
```

---

## 5. Terminal renderer — the moving-gap discipline

The live counter is pinned to the bottom row while results scroll above.
This is genuinely the spiciest part of the codebase, so here's the state machine:

```
INVARIANT (maintained by us, always):
  row above cursor = moving gap (exactly ONE blank row)
  cursor row       = the counter line, cursor parked at end of text, NO newline

Startup:            banner(stderr) leaves blank row = permanent header separator
                    drawProgressLine() parks cursor on counter row

First result:       \r\033[2K  ← replace counter IN PLACE, grow DOWNWARD
                    (keeps the banner separator alive — never consume it)

Later results:      \r\033[1A  ← jump UP onto the gap row
                    print block over it  ← gap gets CONSUMED, results stay tight
                    \033[2K\n ← clear landing row (stale counter residue!!),
                                newline drops a FRESH gap
                    drawProgressLine()

Suppressed writes   (\r + redraw only — counters update, layout untouched)
(--vuln-only SAFE):

Ticker @100ms:      \r\033[K + redraw (spinner + ETA stay ALIVE during slow reqs)

Stop:               \r\033[1A\033[2K\n\033[2K  ← reclaim gap+counter rows
                    WriteSummary prints right there. spacing: consistent. always.
```

Every screen mutation happens under `liveMu`. No relative movement without a
tracked invariant. The `\033[2K` on landing rows is NOT optional — forget it
and every write leaks a stale counter snapshot into scrollback (we learned
this the hard way so you don't have to 💀).

Non-TTY / quiet mode: zero ANSI escapes, plain newline-terminated lines.
Piped output is byte-clean. Verified, not vibes.

---

## 6. Concurrency model

```
                 feeder goroutine
                       │ writes
                       ▼
              jobs chan (buf 256)
                       │ reads ×N
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     worker-1 ...  worker-i ...  worker-N      (-c, default 5)
        │              │              │
        └──────────────┼──────────────┘
                       ▼ writes
             results chan (buf 256)
                       │ reads (single!)
                       ▼
                 main drain loop
                       │
        closer goroutine: wg.Wait → close(results) → range exits
```

- Shared mutable state: `counts[]` atomics + `inflight` atomic. That's IT.
- `http.Client` cloned per-Follow call → per-request `CheckRedirect` closure
  → zero cross-goroutine contamination.
- Ctrl-C: `signal.NotifyContext` cancels ctx → in-flight reqs die → workers
  return → jobs close → results close → drain exits → summary prints. No
  orphaned goroutines, no leaked conns. Clean exit or nothing.

---

## 7. Color system — semantic, not decorative

| Hue | Means | Used for |
|-----|-------|----------|
| green | success | SAFE verdict, 2xx, clean-scan ✓ |
| red | danger | VULN verdict, 5xx, `IP:internal`, `creds:` tags, injected param |
| yellow | warning | ERR verdict, 4xx, `escape@hopN`, `IP:external`, payload value |
| cyan | informational | 3xx redirects, landing URL, rate, active workers |
| bold white | primary data | all counters |
| dim gray | chrome | labels, dots, spinner, ETA |

All via fatih/color → auto-degrades to plain text on pipes / `NO_COLOR`.
Piped output contains ZERO escape bytes. Byte-clean, tested.

---

# Roadmap — v0.2.0 (the realistic one, not the delusional one)

## P0 — actually broken without these

| Item | Why it's an L rn | The fix |
|------|------------------|---------|
| **Body-aware detection** | Default method is HEAD → we literally cannot see `<meta refresh>` or `location.href=` JS redirects. Whole class of open redirects flying under the radar. Not gonna lie, that's a blind spot. | Auto-fallback: HEAD → GET + bounded body read (`io.LimitReader` ~64KB), scan for meta refresh / `window.location` / `document.location` patterns. Land them as new verdict tags. |
| **Error taxonomy** | Summary says `err N` but timeouts/DNS fails/TLS/cancel all blur together. When a target rate-limits you, everything's "err" and you learn nothing. Mid. | Typed error classification in httpclient (timeout/dns/tls/refused/cancel), separate counters, shown in chips + JSON. |
| **Scanner integration tests** | detector/httpclient/output got solid coverage, but `scanner.Run` itself has zero tests. The composition root being untested is a silent killer fr. | httptest matrix: redirect chains, loops, slow targets, ctx-cancel mid-scan, FP-server replay. Assert counters + verdicts. |

## P1 — high value, ships real utility

| Item | The pitch |
|------|-----------|
| **Matchers & filters** | `--exclude-domain`, `--include-status`, `--filter-pattern` so users curate noise THEIR way instead of us guessing. Every serious recon tool has this; without it we're toys. |
| **Rate limiting** | `-rl 100` global req/s cap + optional per-host jitter. Otherwise one angry WAF ban nukes the whole scan and you get to explain that to your manager. |
| **Session resume** | `--session file.json`: persist completed `(url,param,payload)` triples; re-runs skip tested combos. Long scans dying at 90% is a tragedy we can prevent. |
| **Param selection** | `--params redirect,url,next,...` + `--param-regex` — most users only care about redirect-y params. Testing 50 params × 40 payloads on a fat target is just burning someone's WAF quota. |

## P2 — nice upgrades

- **GET-mode body diffing**: hash response bodies to catch same-domain redirects that still leak (open redirect to attacker subdomain takeover vibes).
- **Retry w/ backoff**: 1 retry on transient errors before counting an ERR, halves false err counts on flaky targets.
- **CSV output**: `-o out.csv` next to JSONL — Excel warriors exist, let them eat.
- **`--probe-all-methods`**: try HEAD then GET automatically per-target.
- **Structured logs** (`--verbose`): per-mutation request/response trace to a sidecar file for debugging weird chains.

## P3 — do NOT build these (scope creep alert 🚨)

- ❌ Web dashboard / TUI — it's a CLI tool, a browser UI is cosplay at this stage
- ❌ Passive crawling — different tool, different threat model, different maintenance bill
- ❌ Plugin system — YAGNI until three people actually ask
- ❌ SARIF output — unless someone's piping into GitHub Code Scanning, nobody wants this XML pain
- ❌ Custom DNS resolver pools — you are not building masscan

## Version targets

```
v0.2.x  P0 + P1  →  "trust it on a real assessment" tier
v0.3.x  P2       →  polish + ergonomics
v1.0.0  stable CLI contract, semver promise, goreleaser + docker + CI badges
```

---

*last updated: v0.1.0-dev, post counter-refactor era ✍️*
