# internal/tools — MCP Tool Implementations

## OVERVIEW
All MCP tool handlers. Each tool in its own file, registered centrally in `tools.go:Register()`.

## WHERE TO LOOK
| What | File |
|------|------|
| Tool registration | `tools.go` — `Register()` wires all tools onto the MCP server |
| Remote command execution | `execute_remote.go` — runs SSH commands with approval gate |
| Read remote files | `read_file.go`, `fetch_remote_file.go` — cat/scp remote paths |
| Host inventory | `inventory.go`, `inventory_parse.go`, `inventory_types.go` — OS/package/container scanning |
| CVE lookup | `cve_lookup.go` — local CVE database search |
| Host listing | `list_hosts.go` — enumerates configured hosts |

## CONVENTIONS
- Tool files expose `register*()` functions called from `Register()`
- All tool handlers receive `*ssh.Pool`, `*engine.Engine`, and `*approval.Gate` as needed
- Approval-gated tools use `gate.CheckExecuteRemote()` before executing
- Test files use `_test` package suffix (e.g. `package tools_test`) for black-box testing

## NOTES
- `inventory_parse.go` (208 lines) and `cve_lookup.go` (192 lines) are the largest tool files
- Inventory parsing supports Wazuh client keys format
