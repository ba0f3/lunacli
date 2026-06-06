# cmd — CLI Layer

## OVERVIEW
Cobra CLI commands for `luna`. Root command + subcommands registered via `init()`.

## WHERE TO LOOK
| What | File |
|------|------|
| Root CLI definition | `root.go` — `RootCmd` variable, `Execute()` |
| MCP server entrypoint | `serve.go` — wires all deps, starts stdio server |
| Interactive first-run setup | `onboard.go` — config, embedded policy, Telegram |
| SSH diagnostics | `ssh_debug.go` — `luna ssh-debug <target>` |

## CONVENTIONS
- `log.Fatalf` is acceptable here (top-of-main) — not in library code
- New commands: define `var XCmd = &cobra.Command{…}`, register in `init()`
- Keep `cmd/` thin — all logic in `internal/`
