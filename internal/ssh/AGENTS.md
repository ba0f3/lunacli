# internal/ssh — SSH Connection Pool & Auth

## OVERVIEW
SSH client infrastructure: connection pooling, multi-source authentication (ssh-agent + ssh_config IdentityFile + default `~/.ssh/id_*`), known_hosts verification, and SFTP operations.

## WHERE TO LOOK
| What | File |
|------|------|
| Connection pool | `pool.go` — `Pool` (lazy connect, cache, evict), `Execute()` |
| Host key algorithms | `host_key_algorithms.go` — per-host key algorithm negotiation |
| Known hosts parser | `known_hosts_parser.go` — `~/.ssh/known_hosts` parsing |
| SFTP operations | `sftp.go` — remote file listing/stat via SFTP |
| Auth utilities | `util.go` — shared helpers |

## CONVENTIONS
- `Pool` uses `sync.Mutex` for thread safety; connections cached by target string
- Auth order: ssh-agent first → ssh_config IdentityFile → default keys
- Failed connections are evicted from cache and retried once
- `known_hosts` respects `StrictHostKeyChecking` (no, accept-new, ask)
- `parseTarget()` supports `user@host:port` with `~/.ssh/config` User fallback
