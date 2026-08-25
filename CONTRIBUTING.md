# Contributing

## Dev setup

```bash
git clone https://github.com/yourpwnguy/redirx && cd redirx
make build && ./redirx --help
```

Go 1.24+. No other toolchain deps — `make lint` fetches golangci-lint on first use.

## The one rule that matters

`make check` is the exact gate CI enforces. Run it before pushing; if it
passes locally, CI passes.

```
make check    # fmt + vet + lint + race tests + cross-build
```

## Architecture invariants (don't break these)

1. **`detector` never imports terminal/output code** — it emits
   `DetectionResult` structs, nothing else.
2. **`output` never performs HTTP** — it renders `Result` structs only.
3. **`scanner` is the only composition root** — new wiring goes there,
   not in main/cli.
4. **Shared state is atomics or channels** — no raw mutex-guarded globals
   outside the writer's display lock.

Full details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Commits & releases

- Conventional prefixes keep the changelog clean: `feat:`, `fix:`,
  `docs:`, `test:`, `chore:` — anything with those excluded prefixes
  won't appear in release notes.
- Releases are tag-driven: `git tag vX.Y.Z && git push origin vX.Y.Z`
  and GoReleaser handles the rest.

## Tests

New detection logic needs a table test in the same package. Behavior
fixes need a regression test that fails without the fix — the suite is
fast, there's no excuse not to.
