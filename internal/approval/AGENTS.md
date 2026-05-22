# internal/approval — Out-of-Band Approval Workflow

## OVERVIEW
Largest package in the project (25 files). Implements human-in-the-loop approval for mutating SSH commands via Telegram. Uses in-memory store by default.

## WHERE TO LOOK
| What | File |
|------|------|
| Core policy gate | `gate.go` — `Gate.CheckExecuteRemote()` decides execute/block/permission |
| Service orchestration | `service.go` — `Service` (create, approve, deny, consume, verify) |
| Store interface | `store.go` — `Store` interface, `Record` struct |
| Memory store impl | `store_memory.go` — `NewMemoryStore()` |
| Telegram provider | `provider_telegram.go` — sends approval prompts as messages |
| Telegram polling | `telegram_poll.go` — listens for approve/deny replies |
| Fingerprinting | `fingerprint.go` — SHA-256 body fingerprint + prefix |
| Bootstrapping | `serve_bootstrap.go` — wires providers/stores from config |

## CONVENTIONS
- `Provider` interface in `provider.go` — add new transports by implementing `Notify()`
- Pending request lifecycle: pending → approved/denied → consumed
- Fingerprint the JSON body of every request to detect command drift
- `Error` sentinel values: `ErrNotFound`, `ErrExpired`, `ErrConsumed`, `ErrMismatch`

## NOTES
- Telegram is the only provider today; `providers_env.go` reads bot token/env config
- In-memory store is ephemeral — restarts lose all pending approvals
