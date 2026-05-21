# Luna MCP-only in-memory approval (simplified)

**Date:** 2026-05-22  
**Status:** Implemented (see plan `docs/superpowers/plans/2026-05-22-mcp-inmemory-approval.md`)

**Supersedes:** [2026-05-22-luna-approval-concurrency-and-cli-trust-design.md](./2026-05-22-luna-approval-concurrency-and-cli-trust-design.md) — SQLite, `exec`, CLI `approvals`, and per-process Telegram locks are out of scope for this mode.

## Operator intent

- **One surface:** `luna serve` (stdio MCP) only — no `luna exec`, no `luna approvals`, no `luna telegram poll` subcommand.
- **One approver channel:** Telegram inline buttons only.
- **One process:** MCP server owns Telegram long-poll and approval state in **memory**.
- **No `approvals.db`:** No SQLite persistence for pending/approved records.

## Why this is simpler

| Old problem | Simplified answer |
|-------------|-------------------|
| Many `exec` pollers | No `exec` |
| Agent self-approves via CLI | No CLI approve |
| SQLite + file locks | Single process, in-memory map |
| `serve` does not poll | `serve` starts poll loop at startup |

## Architecture

```text
┌──────────────────────────────────────────────┐
│  luna serve (single OS process)               │
│  ┌────────────────────────────────────────┐ │
│  │ MCP stdio  →  execute_remote           │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ MemoryStore (map approval_id → record) │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ Gate: classify → pending / verify ID   │ │
│  └────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────┐ │
│  │ Telegram: sendMessage + Poll loop       │ │
│  │ (callbacks → Approve/Deny in memory)   │ │
│  └────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
         │                    ▲
         ▼                    │
    SSH execute          Telegram user
```

### Startup (`luna serve`)

1. Load policy + config (Telegram token, approver user id, TTL).
2. Construct `MemoryStore` + `Service` (same API as today, different store backend).
3. Construct `TelegramProvider` (telegram-only; no `fake` provider needed for production).
4. **Start `go tg.Poll(ctx)`** before or with `ServeStdio` — single consumer, in-memory offset optional (process lifetime only; offset can stay in-memory `int64` since one poller).
5. Register MCP tools; block until stdio ends; cancel poll ctx on shutdown.

### `execute_remote` flow (unchanged contract)

1. **Read-only** → SSH immediately.
2. **Mutating, no `approval_id`** → create pending in memory, `Notify` Telegram, return `PERMISSION_REQUIRED` + `approval_id` + expiry.
3. **Mutating + valid `approval_id`** → verify fingerprint/host/command/timeout, mark consumed, SSH.
4. **Forbidden** → `BLOCKED`.

Agent must retry with same host/command/timeout and `approval_id` after human taps Telegram.

### Telegram poll loop

- Runs **inside** `serve` process only.
- `allowed_updates: ["callback_query"]`.
- `HandleCallback` → `svc.Approve` / `svc.Deny` on memory record.
- Edit message to resolved status (keep current HTML formatting).
- No flock file (only one poller by construction).

### Memory store

```go
type MemoryStore struct {
    mu      sync.RWMutex
    records map[string]Record
}
```

Implement `approval.Store` interface (or slim interface used by `Service`):

- `InsertPending`, `Get`, `UpdateStatus`, `MarkConsumed`
- `ListPending` — optional; omit if no CLI
- `AppendAudit` — no-op or stderr-only slice (optional, YAGNI)
- `ExpireDue` — scan map on each Gate touch or ticker in serve
- `SetTelegramMessage` — keep for edit-after-approve (chat_id, message_id on record)
- `Close` — no-op

**TTL:** Same as today (`approval.ttl`); expired entries removed on access or periodic sweep in serve.

### Configuration

| Keep | Remove / ignore |
|------|------------------|
| `policy.yml` | `approval.store` (no db path) |
| `luna.config.json` → `telegram.*` | `approval.provider` (telegram only) |
| `approval.ttl` | `cli.approver_users` |
| | `LUNA_APPROVAL_STORE` |

### CLI surface (removed)

| Remove | Notes |
|--------|-------|
| `cmd/exec.go` | Delete command registration |
| `cmd/approvals.go` | Delete |
| `cmd/telegram.go` | Poll merged into `serve` |
| `RootCmd` with no subcommand | Print usage (no implicit `serve`) |

Optional: keep `ssh-debug` or other debug binaries unrelated.

### Package / code changes (implementation plan preview)

| Area | Action |
|------|--------|
| `internal/approval/store_memory.go` | New in-memory `Store` |
| `internal/approval/service.go` | Works unchanged if `Store` interface satisfied |
| `internal/approval/gate.go` | Unchanged |
| `cmd/serve.go` | Memory store, start Poll goroutine, cancel on exit |
| `internal/approval/providers_env.go` | Only telegram (or telegram required) |
| SQLite store | Keep package for tests; serve does not open it |
| Docs | Rewrite oob-approval + zero-trust for MCP-only |

### Tradeoffs (explicit)

| Benefit | Cost |
|---------|------|
| No Telegram multi-poller races | **Restart `serve` → all pending approvals lost** |
| No agent CLI self-approve | No CLI fallback when Telegram down |
| Minimal moving parts | **Only one MCP process** — second `luna serve` = separate amnesiac state |
| No DB file permissions | No audit trail across restarts |

### Security (same UID as agent)

- Agent still cannot approve without Telegram (no CLI path).
- Telegram `approver_user_id` is the human boundary.
- Agent can still call `execute_remote` with `approval_id` **after** human approved in same server lifetime — correct behavior.

### Testing

- Unit: `MemoryStore` approve/deny/consume/TTL expiry.
- Unit: Gate + memory + fake telegram (httptest).
- Integration: serve does not open sqlite (grep test or serve smoke with memory flag).

### Out of scope

- Persist approvals to disk
- `luna exec` / fleet / CLI operator tools
- flock / offset files
- `fake` provider for local dev (optional: keep for tests only)

## Open assumption

**One `luna serve` process per operator session** (normal for stdio MCP). If OpenCode spawns multiple independent `luna serve` children, each has isolated memory — pending approval on instance A is invisible to instance B. Document this.

## Approval

Pending operator sign-off on this simplified spec before implementation.
