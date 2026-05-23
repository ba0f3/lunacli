# Luna — Zero-Trust Remote SSH Agent

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)]()

**Luna** is a stdio MCP server that gives LLM agents secure, auditable access to remote Linux servers over SSH — with **mandatory out-of-band human approval** for every mutating command.

```
┌─────────────┐     MCP stdio      ┌──────────────┐     SSH      ┌──────────────┐
│  AI Agent   │ ◄──────────────►   │  luna serve  │ ◄─────────► │  Remote Host │
│ (Claude,    │    JSON-RPC        │              │              │              │
│  OpenCode,  │                    │  • classify  │              │  • commands  │
│  goclaw)    │                    │  • gate      │              │  • file I/O  │
└─────────────┘                    │  • approve   │              │  • inventory │
                                   │  • audit     │              └──────────────┘
                                   └──────┬───────┘
                                           │
                                           │ Telegram / CLI
                                           ▼
                                   ┌──────────────┐
                                   │    Human     │
                                   │  Approver    │
                                   └──────────────┘
```

**Never trust the AI agent.** Every command is classified before execution. Read-only ops run immediately. Mutating commands require out-of-band approval. There is no `allow_mutations` self-approval path.

---

## Features

- **🔒 Two‑layer security engine** — Compiled forbidden patterns (irreversible ops like `rm -rf /`, `sudo`, reverse shells) + YAML policy rules
- **🧠 Shell‑aware classification** — Parses commands with `mvdan/sh` to defeat obfuscation (escapes, quotes, substitutions)
- **✅ Out‑of‑band approval** — Mutating commands require human approval via Telegram before execution
- **🔑 Multi‑source SSH auth** — ssh-agent, `IdentityFile` entries from `~/.ssh/config`, and default `~/.ssh/id_*` keys, all with known‑hosts verification
- **📂 Remote file access** — Read files via `cat` or SFTP; fetch files via SCP
- **📊 Host inventory** — Scan remote hosts for OS, packages, containers, and hardware
- **🔍 CVE lookup** — Search bundled CVE data locally
- **📝 Audit logging** — JSON‑lines structured logging to stderr + optional file

---

## Quick Start

### 1. Build

```bash
git clone https://github.com/ba0f3/lunacli.git
cd lunacli
make build
# → ./bin/luna
```

### 2. Configure

Or run interactive setup:

```bash
./bin/luna onboard
```

This writes `luna.config.json`, `luna.d/policy.yml`, skeleton `hosts.yml`, and configures Telegram.

Create a policy file (required) in `./luna.d/policy.yml`:

```yaml
version: 1
rules:
  - action: allow
    hosts: ["*"]
    commands:
      - binary: uptime
      - binary: whoami
      - binary: cat
      - binary: grep

  - action: approve
    hosts: ["*"]
    commands:
      - binary: systemctl
        args_prefix: ["restart"]
      - binary: apt
```

Set up Telegram approval (see [Configuration → Telegram](#telegram)), or use `luna.config.json`:

```json
{
  "config_dir": "./luna.d",
  "approval": { "ttl": "10m" },
  "telegram": {
    "bot_token_file": "/path/to/bot-token",
    "approver_user_id": "123456789"
  }
}
```

Full example configs in [`examples/`](examples/).

### 3. Run

```bash
./bin/luna serve
```

Start your MCP client pointing at `["/path/to/luna", "serve"]`.

### 4. Use

```json
// Read-only command — runs immediately
{
  "host": "web1",
  "command": "uptime"
}

// Mutating command — returns PERMISSION_REQUIRED
{
  "host": "web1",
  "command": "systemctl restart nginx"
}
// → approval_id: abc-123, expires_at: 2026-05-21T17:06:02Z

// After human approves in Telegram, retry with approval_id
{
  "host": "web1",
  "command": "systemctl restart nginx",
  "approval_id": "abc-123"
}
// → executes
```

---

## Architecture

### Security Engine

```
┌─────────────────────────────────────────────────────────────┐
│                  Command Classification                      │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 (compiled, immutable)                              │
│  • Max length check (4 096 chars)                           │
│  • Forbidden patterns: rm -rf /, mkfs, dd, sudo,            │
│    reverse shells, iptables -F, useradd, passwd, ...        │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 (YAML policy)                                      │
│  • Policy rules evaluated top-to-bottom; first match wins   │
│  • Actions: allow (read-only) / approve (OOB) / deny        │
│  • Deny-by-default: unmatched commands → mutating            │
└─────────────────────────────────────────────────────────────┘
```

### Approval Flow

```
Agent                     luna serve                    Human
  │                          │                            │
  │── execute_remote ──────► │                            │
  │   (mutating command)     │                            │
  │                          │── Create pending ──────────│
  │                          │── Notify (Telegram) ──────►│
  │◄── PERMISSION_REQUIRED   │                            │
  │     approval_id: abc     │                            │
  │                          │                   Approve? │◄──── tap button
  │                          │◄─── Approve ──────────────│
  │── execute_remote ──────► │                            │
  │   (same params + id)     │                            │
  │                          │── Verify & Consume         │
  │                          │── SSH execute              │
  │◄── { stdout, exit code } │                            │
```

### SSH Authentication

Authentication order (all sources):

1. **`SSH_AUTH_SOCK`** agent (Bitwarden, 1Password, ssh‑agent)
2. **`~/.ssh/config`** `IdentityFile` entries for the target host
3. **Default keys** (`id_ed25519`, `id_rsa`, `id_ecdsa`)

Known‑hosts verification respects `StrictHostKeyChecking` (`no`, `accept-new`, `ask`).

---

## Configuration

### Config Directory Resolution

Luna looks for `policy.yml` and `hosts.yml` in the first directory found:

| Priority | Path | Set via |
|----------|------|---------|
| 1 | `$LUNA_CONFIG_DIR` | Environment variable |
| 2 | `config_dir` in `luna.config.json` | JSON key |
| 3 | `./luna.d/` | Auto-detect |
| 4 | `~/.config/luna/` | Auto-detect |
| 5 | `/etc/luna/` | Fallback |

### `policy.yml` (Required)

| Field | Purpose |
|-------|---------|
| `version` | Schema version (use `1`) |
| `deny_patterns` | Extra regex patterns → forbidden (supplements compiled list) |
| `rules[]` | Ordered allow/approve/deny rules; first match wins |

Each rule matches by:
- **Hosts** — host identifiers (`*` = all)
- **Tags** — from `hosts.yml` (`*` = any)
- **Commands** — binary name + optional `args_prefix` (prefix match on argv)

**Unmatched commands default to mutating** → `PERMISSION_REQUIRED`.

### `luna.config.json` (Optional)

```json
{
  "config_dir": "./luna.d",
  "approval": { "ttl": "10m" },
  "telegram": {
    "bot_token_file": "/path/to/bot-token",
    "approver_user_id": "123456789",
    "chat_id": "123456789"
  },
  "audit": { "file": "/var/log/luna/audit.jsonl" }
}
```

Config files can be overridden by `LUNA_*` environment variables. See [`docs/oob-approval.md`](docs/oob-approval.md).

### Telegram

1. Create a bot via [@BotFather](https://t.me/BotFather); save the token to a file (`chmod 0600`)
2. Send `/start` to the bot from your Telegram account
3. Find your numeric user ID (use [@userinfobot](https://t.me/userinfobot))
4. Set `approver_user_id` and `bot_token_file` in config or env

---

## MCP Tools

| Tool | Description | Approval |
|------|-------------|----------|
| `execute_remote` | Run a command over SSH | Read-only: no | Mutating: Telegram |
| `read_file` | Read a remote file via shell | No |
| `fetch_remote_file` | Download a remote file via SFTP | No |
| `list_hosts` | List configured hosts from inventory | No |
| `scan_host_inventory` | OS, packages, containers, hardware scan | No |
| `lookup_cve` | Search local CVE database | No |

---

## Commands

```bash
make build        # Build to ./bin/luna
make install      # Build + install to ~/.local/bin/luna
make test         # Run all tests
make lint         # golangci-lint run ./...
make fmt          # go fmt ./...
make fuzz         # Fuzz command classification (5 min)
make tidy         # go mod tidy
```

---

## Project Layout

```
./
├── cmd/                  # cobra CLI (root, serve, ssh-debug)
├── internal/
│   ├── approval/         # OOB approval (Telegram, fingerprints, store)
│   ├── audit/            # JSON event logging
│   ├── config/           # Settings & hosts file loading
│   ├── engine/           # Command classification
│   ├── policy/           # Policy YAML schema & loader
│   ├── security/         # Legacy allowlist (engine supersedes)
│   ├── ssh/              # Connection pool, auth, SFTP
│   └── tools/            # MCP tool handlers
├── docs/                 # Design docs & guides
├── examples/             # Starter configs
└── main.go               # Entry point
```

---

## Related Docs

| Document | What it covers |
|----------|----------------|
| [`docs/oob-approval.md`](docs/oob-approval.md) | Telegram setup, config reference, troubleshooting |
| [`docs/zero-trust-interceptor.md`](docs/zero-trust-interceptor.md) | Security model, migration guide, full config reference |
| [`docs/goclaw-integration.md`](docs/goclaw-integration.md) | Running with goclaw / untrusted MCP clients |
| [`docs/superpowers/`](docs/superpowers/) | Design specs & implementation plans |

---

## License

MIT
