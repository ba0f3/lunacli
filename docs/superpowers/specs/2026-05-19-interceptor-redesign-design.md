# Luna Interceptor Redesign: Zero-Trust Remote SSH Execution

## Overview

Redesign the Luna interceptor from a simple MCP-only SSH proxy into a
comprehensive zero-trust remote command execution system. The binary operates as
both a standalone CLI tool and a stdio MCP server, compatible with any AI agent
(Claude Desktop, Cursor, Cline, OpenCode, etc.).

**Core principle: never trust the AI agent.** All operations are read-only by
default. Every mutating command requires out-of-band human approval through an
external channel — no agent can self-approve.

## Design Decisions

| Decision           | Choice                                                    |
| ------------------ | --------------------------------------------------------- |
| Security model     | Hybrid: compiled Go safety net + YAML policy overlay      |
| Interface          | Full dual-mode: CLI + stdio MCP                           |
| Agent compat       | Any MCP client (agent-agnostic stdio)                     |
| Approval           | Always out-of-band — AI can never self-approve            |
| Approval channels  | CLI baseline + pluggable providers (Telegram built-in)    |
| Policy             | Required `policy.yml` + optional `hosts.yml`              |
| Audit              | Structured JSON to stderr + persistent audit file + CLI   |
| Fleet              | `ssh_plan`, tag-based execution, async tasks              |

## Reference

Inspired by [mcp-ssh-orchestrator](https://github.com/samerfarida/mcp-ssh-orchestrator)
for policy-as-code, fleet execution, and deny-by-default patterns. Luna diverges
by enforcing always-OOB approval (orchestrator has no approval mechanism) and
using a compiled Go safety net as an immutable base layer.

---

## 1. Binary Modes

The `luna-interceptor` binary (renamed to just `luna` for CLI ergonomics)
supports two primary modes plus management subcommands:

### MCP Server Mode
```bash
luna serve                           # stdio MCP server for AI agents
```

### CLI Execution Mode
```bash
luna exec <host> <command>           # execute command (same security engine)
luna plan <host> <command>           # dry-run: classify without executing
```

### Management Subcommands
```bash
luna approvals list                  # list pending approvals
luna approvals approve <id>          # approve a pending mutation
luna approvals deny <id>             # deny a pending mutation
luna audit [--host X] [--since Y]    # query audit log
luna hosts list                      # list inventory (if hosts.yml present)
luna hosts describe <alias>          # host details + tags + policy summary
luna hosts ping <host>               # SSH connectivity check
luna policy check <command>          # test command classification
luna policy validate                 # validate policy.yml syntax
```

All modes share the same security engine, approval gate, and audit trail.

---

## 2. Security Engine (Hybrid Two-Layer)

### Layer 1: Compiled Go (Immutable)

The existing `forbiddenPatterns` in `allowlist.go` become the immutable safety
net. These patterns are compiled into the binary and **cannot be overridden** by
any YAML policy. They catch catastrophic, irreversible operations:

- `rm -rf /` variants
- `mkfs`, `dd if=/dev/zero`, disk destruction
- Fork bombs
- Firewall flush (`iptables -F`)
- Privilege escalation (`sudo`, `su`, `passwd`, `useradd`)
- Kernel module manipulation (`insmod`, `modprobe`, `rmmod`)
- Reverse shell patterns (`/dev/tcp`, `nc -e`, `bash -i`)
- Script execution (`python script.py`, `bash script.sh`)

**Result: FORBIDDEN** — permanently blocked, no approval possible.

The existing `readOnlyPrefixes` and `mutatingPrefixes` are **removed** from the
compiled layer. Their function moves to the YAML policy layer, which is more
flexible and doesn't require rebuilding the binary.

### Layer 2: YAML Policy (Configurable)

`policy.yml` defines what commands are allowed, require approval, or are denied
on which hosts/tags. Evaluated top-to-bottom, first match wins.

Three actions:
- **`allow`** — read-only, auto-execute without approval
- **`approve`** — mutating, requires out-of-band human approval
- **`deny`** — blocked by policy (softer than compiled forbidden)

**Default (no match): deny** — unknown commands are treated as mutating and
require approval. This is the deny-by-default posture.

```yaml
# policy.yml
version: 1

# Additional deny patterns (supplements compiled forbidden list)
deny_patterns:
  - "curl.*--upload-file"
  - "wget.*--post-data"
  - "scp .* remote:"

# Rules evaluated top-to-bottom, first match wins
rules:
  # Observability: safe read-only commands on all hosts
  - action: allow
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: uptime
      - binary: whoami
      - binary: hostname
      - binary: date
      - binary: uname
      - binary: id
      - binary: w
      - binary: who
      - binary: last
      - binary: df
        args_prefix: ["-h"]
      - binary: free
        args_prefix: ["-m"]
      - binary: ps
        args_prefix: ["aux"]
      - binary: top
        args_prefix: ["-bn1"]
      - binary: lsblk
      - binary: lscpu
      - binary: lsmem
      - binary: iostat
      - binary: vmstat
      - binary: ss
      - binary: ip
        args_prefix: ["addr"]
      - binary: ip
        args_prefix: ["link"]
      - binary: ip
        args_prefix: ["route"]
      - binary: ip
        args_prefix: ["neigh"]

  # Log inspection
  - action: allow
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: journalctl
      - binary: cat
      - binary: head
      - binary: tail
      - binary: less
      - binary: grep
      - binary: awk
      - binary: sed     # sed without -i; sed -i caught by compiled mutating flags
      - binary: sort
      - binary: uniq
      - binary: wc
      - binary: cut
      - binary: diff
      - binary: find    # find without -delete/-exec

  # Service status
  - action: allow
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: systemctl
        args_prefix: ["status"]
      - binary: systemctl
        args_prefix: ["is-active"]
      - binary: systemctl
        args_prefix: ["is-enabled"]
      - binary: systemctl
        args_prefix: ["list-units"]
      - binary: systemctl
        args_prefix: ["cat"]

  # Docker read-only
  - action: allow
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: docker
        args_prefix: ["ps"]
      - binary: docker
        args_prefix: ["images"]
      - binary: docker
        args_prefix: ["logs"]
      - binary: docker
        args_prefix: ["inspect"]
      - binary: docker
        args_prefix: ["stats"]
      - binary: docker
        args_prefix: ["info"]
      - binary: docker
        args_prefix: ["version"]

  # kubectl read-only
  - action: allow
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: kubectl
        args_prefix: ["get"]
      - binary: kubectl
        args_prefix: ["describe"]
      - binary: kubectl
        args_prefix: ["logs"]
      - binary: kubectl
        args_prefix: ["top"]

  # Service management (requires approval)
  - action: approve
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: systemctl
        args_prefix: ["restart"]
      - binary: systemctl
        args_prefix: ["start"]
      - binary: systemctl
        args_prefix: ["stop"]
      - binary: systemctl
        args_prefix: ["reload"]
      - binary: systemctl
        args_prefix: ["enable"]
      - binary: systemctl
        args_prefix: ["disable"]

  # Package management (requires approval)
  - action: approve
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: apt
      - binary: apt-get
      - binary: yum
      - binary: dnf
      - binary: pip
      - binary: npm

  # File operations (requires approval)
  - action: approve
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: cp
      - binary: mv
      - binary: mkdir
      - binary: rm
      - binary: touch
      - binary: chmod
      - binary: chown
      - binary: tee
      - binary: tar
      - binary: unzip

  # Docker mutations (requires approval)
  - action: approve
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: docker
        args_prefix: ["start"]
      - binary: docker
        args_prefix: ["stop"]
      - binary: docker
        args_prefix: ["restart"]
      - binary: docker
        args_prefix: ["rm"]
      - binary: docker
        args_prefix: ["pull"]
      - binary: docker
        args_prefix: ["run"]
      - binary: docker
        args_prefix: ["exec"]

  # Everything else: implicit deny (treated as mutating, requires approval)
```

### Classification Flow

```
Command received
    │
    ├── Length > 4096? → FORBIDDEN (DoS protection)
    │
    ├── Matches compiled forbiddenPatterns? → FORBIDDEN
    │
    ├── Parse with mvdan/sh → extract binary + args
    │
    ├── Contains redirect (>) or substitution ($())? → MUTATING
    │
    ├── Matches compiled mutatingFlagPatterns (sed -i, etc.)? → MUTATING
    │
    ├── Match against policy.yml rules (top-to-bottom):
    │   ├── action: allow → READ-ONLY (auto-execute)
    │   ├── action: approve → MUTATING (require OOB approval)
    │   └── action: deny → DENIED (blocked by policy)
    │
    └── No match → MUTATING (deny-by-default)
```

---

## 3. Approval System (Always Out-of-Band)

### Key Changes

- The `allow_mutations` parameter is **removed entirely** from `execute_remote`.
  No agent can self-approve.
- The `ModeLocal` / `ModeRemote` distinction is **removed**. There is only one
  mode: always out-of-band. The `LUNA_APPROVAL_MODE` env var is removed.
- Every mutating command must be approved through an external channel (CLI,
  Telegram, or other provider).

### Flow

1. Agent (or CLI user) submits a mutating command
2. Security engine classifies as `MUTATING`
3. Interceptor creates a pending approval record (SQLite)
4. Returns `PERMISSION_REQUIRED` with:
   - `approval_id` — UUID for retry
   - `expires_at` — RFC3339 UTC deadline
   - `fingerprint_prefix` — short hash for verification
   - `command` — the redacted command for review
   - `host` — target host
5. Providers notify through configured channels (Telegram, etc.)
6. Human approves via:
   - CLI: `luna approvals approve <id>`
   - Telegram: tap approve/deny button
   - Future: Slack, Discord, webhook
7. Agent retries with same `host`, `command`, `timeout_sec`, and `approval_id`
8. Interceptor verifies approval → executes → audits

### Approval Providers (Pluggable)

```go
// Provider interface (existing, cleaned up)
type Provider interface {
    Name() string
    Notify(pending PendingApproval, req Request) error
    // HandleCallback is provider-specific (Telegram bot, webhook, etc.)
}
```

Built-in providers:
- **CLI** — always available, no configuration needed
- **Telegram** — existing implementation, cleaned up

Provider interface is open for future channels (Slack, Discord, webhook).

### Approval for Fleet Operations

When `ssh_run_on_tag` targets multiple hosts, the system creates **one approval
per host** for mutating commands. The human sees a summary like:

```
Pending approvals for: systemctl restart nginx
  [abc123] web-prod-1 (10.0.1.10) — awaiting
  [def456] web-prod-2 (10.0.1.11) — awaiting
  [ghi789] web-prod-3 (10.0.1.12) — awaiting

Approve all: luna approvals approve abc123 def456 ghi789
```

This preserves per-host auditability while allowing batch approval from the CLI.

---

## 4. Policy Configuration

### File Locations

Luna searches for config files in this order:
1. Path specified by `LUNA_CONFIG_DIR` environment variable
2. `./luna.d/` (current working directory)
3. `~/.config/luna/`
4. `/etc/luna/`

### Required: policy.yml

Defines command classification rules. **Must exist** — Luna refuses to start
without it.

Structure documented in Section 2 above.

### Optional: hosts.yml

Defines known host inventory with tags and metadata. When present, provides:
- Tag-based execution (`ssh_run_on_tag`)
- Per-host policy rules
- Host discovery (`list_hosts`, `describe_host`)

When absent, hosts are specified ad-hoc and only global policy rules apply.
Tag-based operations are unavailable.

```yaml
# hosts.yml
version: 1

hosts:
  - alias: web-prod-1
    host: ubuntu@10.0.1.10
    tags: [web, production]
    description: "Production web server 1"

  - alias: web-prod-2
    host: ubuntu@10.0.1.11
    tags: [web, production]
    description: "Production web server 2"

  - alias: db-staging
    host: postgres@10.0.2.20:2222
    tags: [database, staging]
    description: "Staging PostgreSQL server"

  - alias: monitoring
    host: admin@10.0.3.5
    tags: [monitoring, infrastructure]
    description: "Prometheus + Grafana host"
```

---

## 5. MCP Tools (Agent-Agnostic)

All tools communicate via MCP stdio protocol. Compatible with any MCP client.

### Discovery & Planning

| Tool | Description |
| --- | --- |
| `list_hosts` | List configured hosts (from hosts.yml or SSH config) |
| `describe_host` | Host details, tags, and policy summary |
| `ssh_plan` | Dry-run: classify command, show what would happen, no execution |
| `ssh_ping` | Verify SSH connectivity to a host |

### Execution

| Tool | Description |
| --- | --- |
| `execute_remote` | Single-host command execution. Read-only auto-executes; mutating returns PERMISSION_REQUIRED |
| `ssh_run_on_tag` | Execute across all hosts matching a tag. Creates per-host approvals for mutations |

### Async Tasks

| Tool | Description |
| --- | --- |
| `ssh_run_async` | Start a long-running command in background, returns task_id |
| `ssh_task_status` | Check async task progress (running/done/failed/cancelled) |
| `ssh_task_output` | Stream output from an async task |
| `ssh_task_cancel` | Cancel a running async task |

### File Operations (Read-Only)

| Tool | Description |
| --- | --- |
| `read_file` | Read file via SFTP (capped at max_kb) |
| `fetch_remote_file` | Download file via SFTP (capped at max_kb) |

### Removed Parameters

- `allow_mutations` — **removed** from `execute_remote`. Agents cannot
  self-approve.

### Changed Parameters

- `approval_id` — now the **only** way to authorize a mutating command.
  Returned from the initial `PERMISSION_REQUIRED` response.

---

## 6. Audit Logging

### Dual Output

1. **Structured JSON to stderr** — real-time, captured by process supervisor
2. **Append to audit file** — persistent, queryable via `luna audit`

Audit file location: `LUNA_AUDIT_FILE` env var, default `~/.config/luna/audit.jsonl`

### Event Types

```json
{
  "timestamp": "2026-05-19T19:40:00.123Z",
  "event": "command_classified",
  "host": "ubuntu@10.0.1.10",
  "command": "systemctl status nginx",
  "classification": "read-only",
  "policy_rule": "observability/service-status",
  "source": "mcp"
}
```

```json
{
  "timestamp": "2026-05-19T19:40:00.456Z",
  "event": "command_executed",
  "host": "ubuntu@10.0.1.10",
  "command": "systemctl status nginx",
  "classification": "read-only",
  "exit_code": 0,
  "duration_ms": 142,
  "source": "mcp"
}
```

```json
{
  "timestamp": "2026-05-19T19:41:00.789Z",
  "event": "approval_requested",
  "host": "ubuntu@10.0.1.10",
  "command": "systemctl restart nginx",
  "classification": "mutating",
  "approval_id": "abc-123-def",
  "expires_at": "2026-05-19T19:56:00Z",
  "source": "mcp"
}
```

```json
{
  "timestamp": "2026-05-19T19:42:00.000Z",
  "event": "approval_granted",
  "approval_id": "abc-123-def",
  "approved_by": "cli",
  "source": "cli"
}
```

```json
{
  "timestamp": "2026-05-19T19:42:01.234Z",
  "event": "command_blocked",
  "host": "ubuntu@10.0.1.10",
  "command": "rm -rf /",
  "classification": "forbidden",
  "reason": "compiled safety net: catastrophic operation",
  "source": "mcp"
}
```

### CLI Queries

```bash
luna audit                              # recent events
luna audit --host ubuntu@10.0.1.10      # filter by host
luna audit --event command_executed      # filter by event type
luna audit --since 2026-05-19T00:00:00Z # filter by time
luna audit --classification mutating    # filter by classification
luna audit --json                       # raw JSON output
```

---

## 7. Fleet Execution

### Tag-Based Execution

`ssh_run_on_tag` runs a command across all hosts matching a tag from `hosts.yml`.

- Read-only commands execute immediately on all matching hosts
- Mutating commands create one pending approval **per host**
- Execution uses bounded concurrency (configurable, default 5)
- Results are aggregated per host

### Async Tasks

For long-running commands (e.g. package upgrades, log analysis):

1. `ssh_run_async` starts the command, returns a `task_id`
2. `ssh_task_status` polls for progress
3. `ssh_task_output` streams output (with optional `offset` for incremental reads)
4. `ssh_task_cancel` sends SIGTERM to the remote process

Async tasks are tracked in-memory with configurable max concurrent tasks.
Task state is not persisted across restarts (deliberate — tasks are ephemeral).

---

## 8. Package Structure (Redesigned)

```
interceptor/
├── main.go                          ← entrypoint, dispatches CLI vs MCP
├── cmd/                             ← CLI commands (cobra)
│   ├── root.go                      ← root command + global flags
│   ├── serve.go                     ← luna serve (MCP stdio)
│   ├── exec.go                      ← luna exec <host> <cmd>
│   ├── plan.go                      ← luna plan <host> <cmd>
│   ├── approvals.go                 ← luna approvals list|approve|deny
│   ├── audit.go                     ← luna audit [filters]
│   ├── hosts.go                     ← luna hosts list|describe|ping
│   └── policy.go                    ← luna policy check|validate
├── internal/
│   ├── engine/                      ← unified classification engine
│   │   ├── engine.go                ← orchestrates hardcoded + policy layers
│   │   ├── hardcoded.go             ← immutable forbidden patterns (from allowlist.go)
│   │   ├── hardcoded_test.go
│   │   ├── parser.go                ← shell command parser (mvdan/sh)
│   │   └── parser_test.go
│   ├── policy/                      ← YAML policy loading + matching
│   │   ├── loader.go                ← parse + validate policy.yml
│   │   ├── loader_test.go
│   │   ├── matcher.go               ← match commands against rules
│   │   ├── matcher_test.go
│   │   └── types.go                 ← policy data structures
│   ├── config/                      ← configuration management
│   │   ├── config.go                ← config dir resolution + loading
│   │   ├── hosts.go                 ← hosts.yml loader
│   │   └── hosts_test.go
│   ├── ssh/                         ← SSH connection pool (largely unchanged)
│   │   ├── pool.go
│   │   ├── sftp.go
│   │   ├── host_key_algorithms.go
│   │   ├── known_hosts_parser.go
│   │   └── util.go
│   ├── approval/                    ← approval system (enhanced)
│   │   ├── gate.go                  ← always-OOB gate (allow_mutations removed)
│   │   ├── service.go               ← approval state machine
│   │   ├── store.go                 ← store interface
│   │   ├── store_sqlite.go          ← SQLite implementation
│   │   ├── provider.go              ← provider interface
│   │   ├── provider_telegram.go     ← Telegram provider
│   │   ├── redact.go                ← command redaction
│   │   ├── fingerprint.go           ← request fingerprinting
│   │   └── mode.go                  ← approval mode config
│   ├── audit/                       ← structured audit logging
│   │   ├── logger.go                ← JSON logger (stderr + file)
│   │   ├── event.go                 ← event type definitions
│   │   └── query.go                 ← audit file querying for CLI
│   ├── fleet/                       ← multi-host execution
│   │   ├── executor.go              ← tag-based execution + concurrency
│   │   ├── executor_test.go
│   │   ├── async.go                 ← async task manager
│   │   └── async_test.go
│   └── tools/                       ← MCP tool handlers
│       ├── tools.go                 ← tool registration
│       ├── execute_remote.go        ← single-host execution
│       ├── plan.go                  ← ssh_plan (dry-run)
│       ├── run_on_tag.go            ← tag-based fleet execution
│       ├── async_tasks.go           ← async task tools
│       ├── read_file.go             ← SFTP read (unchanged)
│       ├── fetch_remote_file.go     ← SFTP download (unchanged)
│       ├── list_hosts.go            ← host listing
│       ├── describe_host.go         ← host details
│       ├── ping.go                  ← connectivity check
│       └── inventory.go             ← host inventory scanning
```

### Key Structural Changes

- `internal/security/` → split into `internal/engine/` (classification) and
  `internal/policy/` (YAML rules). Clear separation of immutable vs configurable.
- `internal/audit/` — new package for structured logging
- `internal/fleet/` — new package for multi-host + async
- `internal/config/` — new package for config file management
- `cmd/` — Cobra CLI commands (currently only has `ssh-debug`)
- `allow_mutations` parameter removed from gate and execute_remote

### Dependencies

- **Existing**: `mvdan.cc/sh/v3` (shell parser), `github.com/mark3labs/mcp-go`
  (MCP server), `github.com/pkg/sftp`, `golang.org/x/crypto/ssh`
- **New**: `github.com/spf13/cobra` (CLI framework),
  `gopkg.in/yaml.v3` (policy/hosts parsing)
- **Existing retained**: `modernc.org/sqlite` (approval store)

---

## 9. Migration Path

This is a redesign, not a rewrite. Existing code is refactored:

1. `security/allowlist.go` → `engine/hardcoded.go` (forbiddenPatterns +
   mutatingFlagPatterns kept; readOnlyPrefixes + mutatingPrefixes removed)
2. `security/allowlist.go` Classify() → `engine/engine.go` Classify() (now
   two-layer: hardcoded first, then policy)
3. `approval/gate.go` → simplified (remove local allow_mutations path, always
   require OOB)
4. `tools/execute_remote.go` → updated (remove allow_mutations param, always
   go through approval for mutating)
5. All existing tests updated to reflect new classification paths
6. New tests for policy loading, matching, audit, fleet

---

## 10. Non-Goals (Explicit Exclusions)

- **No credential management in config** — SSH auth continues to use local SSH
  agent and default keys (`~/.ssh/id_*`). No `credentials.yml`.
- **No network CIDR allowlists** — Luna relies on SSH reachability, not IP
  filtering. The operator's firewall handles network policy.
- **No container isolation** — Luna runs as a native binary, not in Docker.
  Container deployment is possible but not a design goal.
- **No web UI** — CLI and Telegram are the approval interfaces. No dashboard.
- **No multi-user RBAC** — single operator model. The human approving is
  trusted.
