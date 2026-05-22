# PROJECT KNOWLEDGE BASE

**Generated:** Fri May 22 2026
**Commit:** f0427d0
**Branch:** main

## OVERVIEW
Zero-trust secure remote SSH agent + stdio MCP server (`luna`). Written in Go 1.25 using cobra for CLI and mark3labs/mcp-go for the MCP protocol layer. Enables LLM-driven remote server management with out-of-band approval gates.

## STRUCTURE
```
./
├── cmd/          # cobra CLI (root, serve, ssh-debug)
├── internal/
│   ├── approval/ # OOB approval workflow (Telegram, fingerprints, store)
│   ├── audit/    # JSON event logging
│   ├── config/   # Settings & hosts file loading
│   ├── engine/   # Command classification (read-only/mutating/forbidden)
│   ├── policy/   # Policy YAML schema & loader
│   ├── security/ # Command allowlist (legacy — engine supersedes)
│   ├── ssh/      # Connection pool, auth, SFTP
│   └── tools/    # MCP tool registrations
├── docs/         # Design docs (approval flows, integration)
└── main.go       # Entry point
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Add CLI command | `cmd/` | Register on `RootCmd` |
| Add MCP tool | `internal/tools/tools.go` | Wire in `Register()` |
| Change approval flow | `internal/approval/` | Gate, Service, Store interfaces |
| Modify SSH logic | `internal/ssh/` | Pool, auth, host keys |
| Change command classification | `internal/engine/` | Or `internal/security/` (legacy) |
| Policy YAML schema | `internal/policy/types.go` | |
| Config loading | `internal/config/` | Settings + hosts |

## CONVENTIONS
- **Constructor pattern**: `New*()` returns struct; no config structs in constructors unless needed
- **Error handling**: Wrap with `fmt.Errorf("context: %w", err)`. Log to stderr via `log.Printf`. Fatal only in `cmd/` layer
- **Testing**: Standard `testing` package, table-driven with `t.Run` subtests, `t.Fatalf` on unexpected errors
- **Exported symbols**: Only what's consumed across packages
- **MCP tools**: Register in `tools/tools.go`, implement in separate files per tool

## COMMANDS
```bash
make build    # Build to ./bin/luna
make install  # Build + install to ~/.local/bin/luna
make test     # go test ./...
make lint     # golangci-lint run ./...
make fmt      # go fmt ./...
make fuzz     # Fuzz command classification in internal/security/
```

## NOTES
- `internal/security/allowlist.go` and `internal/engine/engine.go` both classify commands. `engine` is the newer layer that respects policy YAML; `security` is the legacy allowlist still used as fallback.
- Audit logs go to stderr as JSON and optionally to a file.
- The `approval` package is the largest and most complex — has its own AGENTS.md.
