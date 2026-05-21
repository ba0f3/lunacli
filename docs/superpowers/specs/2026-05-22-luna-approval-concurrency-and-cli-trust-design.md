# Luna approval concurrency and CLI trust boundary

**Date:** 2026-05-22  
**Status:** Approved in brainstorming (pending implementation plan)

## Problem statement

Two related issues affect production use when multiple AI agents (or terminals) run Luna at the same time, with the agent process running as the **same Unix UID** as the human operator.

### 1. Telegram polling conflicts

Each `luna exec` that waits for approval starts its own `getUpdates` long-poll loop with an in-memory `offset` starting at zero. Multiple concurrent waiters cause:

- Duplicate delivery of the same `callback_query` to multiple processes
- Redundant HTTP long polls (30s each) on one bot token
- Racy double-handling of approve/deny (usually harmless due to SQLite state machine, but noisy and undefined vs Telegram’s single-consumer model)

SQLite `WaitForDecision` (1s poll) is safe across processes; Telegram is not.

### 2. CLI approve in the same binary as the agent

`luna approvals approve` / `deny` live in the same binary as `luna serve` and `luna exec`. Authorization today is `os.Getuid()` ∈ `cli.approver_users`. When the agent runs as the operator’s UID, it can invoke:

```bash
luna approvals approve <approval_id>
```

and bypass the intent of out-of-band human approval without Telegram.

Telegram approval remains true OOB (separate device/account). CLI approval must not be automatable by the agent in the default same-UID deployment.

## Goals

| Goal | Measure |
|------|---------|
| Single Telegram consumer per bot token | At most one process holds poll lock and calls `getUpdates` with a shared monotonic offset |
| Safe concurrent waits | Many `exec` / MCP sessions can wait on distinct `approval_id` rows without Telegram conflicts |
| Human-only CLI approve/deny | Agent-driven non-interactive runs cannot approve; interactive terminal required |
| One binary | No separate `luna-approver` artifact; runtime gates + lock files only |
| Preserve UX | Telegram buttons + CLI approve in a real terminal; `list`/`show` still usable for visibility |

## Non-goals

- Second binary or build tags (operator rejected split binary)
- Setuid / setgid approver
- Blocking read-only `approvals list` / `show` for agents
- External queue (Redis) for approvals
- Preventing a determined agent from allocating a pseudo-TTY (`script`, `ssh -t`) — documented as v1 limit

## Context (current architecture)

| Component | Behavior today |
|-----------|----------------|
| `luna serve` | MCP `execute_remote` → gate → pending row → optional Telegram notify; no blocking wait |
| `luna exec` | Gate → wait → `WaitForDecision` + background `TelegramProvider.Poll()` per process |
| `luna approvals approve` | UID allow list only |
| `luna telegram poll` | Long poll until interrupt |
| Storage | SQLite `approvals.db`, WAL + busy timeout |

## Design

### Trust boundaries

```text
┌─────────────────────────────────────────────────────────┐
│  Untrusted: luna serve / MCP / agent-driven luna exec   │
│  May: classify, create pending, WaitForDecision, SSH     │
│  May NOT: approvals approve/deny (non-interactive)       │
└───────────────────────────┬─────────────────────────────┘
                            │ SQLite (approvals.db)
┌───────────────────────────▼─────────────────────────────┐
│  Trusted human paths:                                    │
│  • Telegram (configured approver_user_id + buttons)      │
│  • luna approvals approve/deny in a real terminal (TTY)  │
│  • luna telegram poll (optional dedicated terminal)        │
└─────────────────────────────────────────────────────────┘
```

### Telegram: single consumer

**Lock file:** `{dirname(approval.store)}/telegram.poll.lock`

- Exclusive `flock(LOCK_EX)` on an open file descriptor for the lifetime of polling.
- Lock released automatically when the holding process exits.

**Offset persistence:** `{dirname(approval.store)}/telegram.update_offset`

- JSON: `{"offset": <int64>}` (Telegram `update_id + 1` after last processed update).
- Read before each `getUpdates`; write after processing each batch (same transaction as audit is optional).

**`Poll(ctx)` lifecycle:**

1. Acquire lock (caller chooses blocking vs non-blocking — see below).
2. Load offset from file (default 0).
3. Loop: `getUpdates(offset, timeout=30, allowed_updates=["callback_query"])`, handle callbacks, advance offset.
4. On `ctx` cancel or error exit: release lock (close fd).

**Callers:**

| Caller | Lock mode | Poll? |
|--------|-----------|-------|
| `luna telegram poll` | Blocking flock | Yes, until signal |
| `luna exec` (waiting) | Try flock (non-blocking) | If acquired, goroutine polls until wait ends; else DB-only wait + stderr hint |
| `luna serve` / MCP | Never | No |

**Stderr hint when not polling:**

```text
warning: Telegram poll not active in this process (another luna holds the lock).
Approve via Telegram in another session, run: luna telegram poll
```

**Spiky concurrency:** First waiter may become poller; others rely on SQLite + Telegram in the holder. Operator can run `luna telegram poll` in a dedicated terminal during bursts so all `exec` instances only DB-wait.

**Failure recovery:** If the lock holder crashes, the kernel releases flock; the next acquirer continues from persisted offset (no replay of acknowledged updates).

### CLI: human-only approve/deny

**`approvals approve` and `approvals deny` must pass `RequireHumanTerminal()`:**

- `stdin` is a terminal (`Isatty`)
- `stdout` is a terminal (`Isatty`)
- Failure: exit 1, clear error, audit event `cli_approve_rejected_non_interactive` / `cli_deny_rejected_non_interactive`

**Defense in depth — agent session marker:**

- `serve` and `exec` set `LUNA_AGENT_SESSION=1` in the process environment at command start (internal, not documented for operators to set).
- If `LUNA_AGENT_SESSION=1` during approve/deny: reject, audit `cli_approve_rejected_agent_session`.
- Not sufficient alone (agent can unset); paired with TTY requirement for real security in the common case.

**`cli.approver_users`:** Retained as secondary check on multi-user machines.

**Read-only subcommands:** `approvals list`, `approvals show` — no TTY requirement (agents may inspect pending requests).

### Package layout (implementation)

| Unit | Responsibility |
|------|----------------|
| `internal/approval/telegram_poller.go` (new) | Lock acquire/release, offset load/save, `RunPoll(ctx, tg, blocking bool)` |
| `internal/approval/telegram_poll.go` | Refactor `Poll` to use shared offset; callback handling unchanged |
| `internal/approval/cli_auth.go` | `RequireHumanTerminal()`, agent session check |
| `cmd/exec.go` | Try non-blocking poller; set agent session env |
| `cmd/serve.go` | Set agent session env; no Telegram poll |
| `cmd/approvals.go` | Gate approve/deny only |
| `cmd/telegram.go` | Blocking poller |

### Error handling and audit

| Event | When |
|-------|------|
| `cli_approve_rejected_non_interactive` | approve/deny without TTY |
| `cli_approve_rejected_agent_session` | approve/deny with `LUNA_AGENT_SESSION=1` |
| Existing unauthorized UID | unchanged |

### Testing

| Test | Type |
|------|------|
| Approve with stdin piped → fails | unit / exec test |
| Approve with `LUNA_AGENT_SESSION=1` → fails | unit |
| Two processes: A holds lock and polls; B try-lock fails, B wakes on DB after A approves | integration with httptest Telegram |
| Offset file advances; second process continues from saved offset | integration |
| `list` without TTY → succeeds | unit |

### Documentation updates

- `docs/oob-approval.md` — single poller, TTY requirement for CLI approve, burst guidance (`luna telegram poll`)
- `docs/zero-trust-interceptor.md` — trust boundary table
- `examples/luna.d/README.md` — short operator note

### Known limitations (v1)

| Limitation | Mitigation |
|------------|------------|
| Same UID can read all config files | TTY gate for CLI; Telegram OOB |
| Agent could use pseudo-TTY to fake interactivity | Document; v2 optional one-time code in Telegram message |
| Agent could run full path to binary with crafted env | `LUNA_AGENT_SESSION` + TTY; not cryptographically strong |
| Running agent under a dedicated service account | Recommended hardening; stronger than TTY alone |

### Future (out of scope)

- v2: One-time approve code displayed only on Telegram (CLI prompts for code)
- v2: Separate OS user for agent processes
- systemd user unit template for `luna telegram poll`

## Decision log

| Decision | Rationale |
|----------|-----------|
| One binary + TTY gate | User constraint; practical for IDE/agent non-interactive subprocesses |
| flock + offset file | Simple, no DB schema change required for offset (file sufficient) |
| `serve` never polls | MCP clients must not hold Telegram consumer; operator or `exec` winner polls |
| Keep `list`/`show` open | Observability for agents without mutating trust |

## Approval

Brainstorming sections §1–§4 approved by operator on 2026-05-22.

Next step: **writing-plans** skill → implementation plan with tasks and verification commands.
