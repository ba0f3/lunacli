# Allowlist and Security Fuzzing — Design Spec

**Date:** 2026-05-15  
**Status:** Approved (brainstorming)  
**Scope:** `interceptor/internal/security` — primary target `Classify`, secondary `unescape`

## Summary

Integrate **native Go `testing.F` fuzzing** to stress-test command classification in `allowlist.go`. Goals combine **robustness** (no panics, hangs, or runaway resource use) and **security oracles** (invariants that encode the fail-safe security model). AFL++/external harnesses are out of scope for phase 1.

## Goals

1. **Robustness:** `Classify` and `unescape` never panic, hang, or exhaust memory on arbitrary inputs within fuzz time limits.
2. **Security oracles:** Fuzz fails when checkable invariants of the security model are violated.

## Non-Goals

- Proving correct classification for arbitrary unknown commands (default-deny to `Mutating` is intentional).
- AFL++/libFuzzer CI integration in phase 1.
- Fuzzing `execute_remote`, SSH pool, or known_hosts in phase 1 (listed as phase 2).

## Success Criteria

| Criterion | Verification |
|-----------|--------------|
| No crashes | Fuzz with `-race` in CI |
| No hangs | Fuzz time budget; early reject for `len(cmd) > maxCommandLen` |
| Corpus regression | Committed seeds replay on every `make test` |
| Oracle violations fail fast | Property checks in `FuzzClassify` |
| CI budget | ~45s fuzz on PR; optional longer nightly |

## Approach

**Recommended:** Native Go `testing.F` (Go 1.25.x), seeded from `allowlist_test.go` cases plus hand-crafted attack shapes (pipes, redirects, escapes, path-qualified binaries). Light structured bias via corpus seeds only — no custom mutator framework.

**Rejected for phase 1:** AFL++ / cgo harness (high CI cost, poor fit for pure Go + `mvdan.cc/sh`).

## Architecture

```
interceptor/
  internal/security/
    allowlist.go              # Classify (existing)
    allowlist_test.go         # table tests (existing)
    allowlist_fuzz_test.go    # FuzzClassify, optional FuzzUnescape
  testdata/fuzz/
    FuzzClassify/             # committed seed corpus
    FuzzUnescape/             # optional
```

### Fuzz Targets

| Target | Input | Purpose |
|--------|--------|---------|
| `FuzzClassify` | `[]byte` → `string` | Main surface: parse, walk AST, regex, prefixes |
| `FuzzUnescape` | `[]byte` → `string` | Isolated escape-handling logic |

`execute_remote.go` calls `security.Classify`; fuzzing the classifier covers the execution gate without a separate MCP harness.

## Robustness Checks (every fuzz input)

- Must not panic (implicit via fuzz runner).
- Complete within per-input deadline (fuzz timeout + built-in length cap at 4096 runes).
- `len(cmd) > maxCommandLen` ⇒ `Forbidden` with non-empty `Reason`.

## Security Oracles

Properties checked inside `FuzzClassify` (fail with `f.Fatalf` / `t.Fatalf`):

1. **Domain:** `Class` ∈ {`ReadOnly`, `Mutating`, `Forbidden`} only.
2. **ReadOnly hygiene:** `ReadOnly` ⇒ `Reason == ""`.
3. **Forbidden/mutating hygiene:** `Forbidden` or `Mutating` ⇒ `Reason != ""`.
4. **Raw forbidden patterns:** If raw `cmd` matches any entry in `forbiddenPatterns`, result must be `Forbidden`.
5. **Parse failure policy:** Unparseable input ⇒ `Mutating` (never `ReadOnly`).
6. **Redirect/substitution:** Parsed `>` redirect or cmd/proc substitution ⇒ at least `Mutating`.
7. **Idempotence:** `Classify(cmd) == Classify(strings.TrimSpace(cmd))` for the same logical string after trim.
8. **Regression seeds:** All `allowlist_test.go` cases included as corpus seeds.

**Not fuzz-oracled:** Whether an unknown command “should” be read-only — unknown commands must remain `Mutating`.

### Optional helper oracles (implement if low-cost)

- Reconstructed static call strings that match `forbiddenPatterns` must not yield `ReadOnly`.
- Dynamic base command (`<DYNAMIC>`) must not yield `ReadOnly`.

## Corpus Strategy

1. Export every `TestClassify`, `TestClassifyOrder`, bypass, escaping, and path-qualified case as seed files under `testdata/fuzz/FuzzClassify/`.
2. Add minimal attack-shape seeds: `;`, `|`, `&&`, `||`, `>`, `>>`, `$(...)`, backticks, `\` escapes, `/usr/bin/` prefixes.
3. Check in minimized crashers from local fuzz runs as regression artifacts.

## CI and Makefile

### Makefile targets

| Target | Command | Use |
|--------|---------|-----|
| `test` | `go test ./...` | Unit tests + corpus replay (no long fuzz) |
| `fuzz` | `go test -fuzz=FuzzClassify -fuzztime=5m ./internal/security/` | Local dev |
| `fuzz-race` | same with `-race` | Local / optional CI |

### `interceptor-ci.yml`

After existing `make test`:

```yaml
- name: Fuzz (bounded)
  run: go test -fuzz=FuzzClassify -fuzztime=45s -race ./internal/security/
```

Optional follow-up: `workflow_dispatch` or scheduled job with `-fuzztime=15m` (not required for phase 1 merge).

## Phase 2 (future)

- Fuzz `execute_remote` validation (host, timeout) with mocked SSH.
- Fuzz `internal/ssh` known_hosts / ssh_config parsers if they grow in complexity.

## Testing Plan (implementation)

1. Add `allowlist_fuzz_test.go` with `FuzzClassify` and oracles.
2. Generate seed corpus from existing table tests.
3. Run `make fuzz` locally until stable; commit seeds.
4. Wire CI fuzz step; confirm green on PR.
5. Document `make fuzz` in `AGENTS.md` or interceptor README (one line).

## References

- `interceptor/internal/security/allowlist.go` — `Classify`, `maxCommandLen`, forbidden/mutating patterns
- `interceptor/internal/security/allowlist_test.go` — regression cases and prefix-priority tests
- `interceptor/internal/tools/execute_remote.go` — consumer of `Classify`
