# Out-of-band (OOB) approval configuration

How to configure human approval for mutating remote commands after the
zero-trust interceptor redesign.

**Related:** [zero-trust-interceptor.md](zero-trust-interceptor.md) (policy +
engine), [examples/luna.d/env.example](../examples/luna.d/env.example)

OOB approval is **not** configured in `policy.yml` or `hosts.yml`. Settings come
from JSON config files, then **environment variables** override. Every mutating
`execute_remote` requires a human decision; agents cannot self-approve.

### Configuration precedence (lowest → highest)

1. `~/.config/luna/config.json`
2. `./luna.config.json` (overrides user file)
3. Environment variables (`LUNA_*`) — always win

Example: [examples/luna.config.json](../examples/luna.config.json)

**Removed (do not use):**

- MCP parameter `allow_mutations`
- `LUNA_APPROVAL_MODE` (`local` / `remote`)

---

## How it works

1. Agent (or CLI) runs a command classified as **mutating** by `policy.yml` + the compiled engine.
2. Interceptor inserts a pending row in SQLite and returns `PERMISSION_REQUIRED` with:
   - `approval_id` — single-use retry token
   - `expires_at` — RFC3339 UTC deadline
   - `fingerprint_prefix` — short hash prefix for human verification
   - redacted command text and host
3. Notification providers (optional) alert the operator.
4. Human approves or denies via CLI or Telegram.
5. Agent retries **`execute_remote`** with the **same** `host`, `command`, `timeout_sec`, and `approval_id`.
6. Gate verifies and **consumes** the approval, then SSH executes.

Read-only commands matching an `allow` rule skip this flow.

---

## JSON config files

| File | Scope |
| ---- | ----- |
| `~/.config/luna/config.json` | User defaults |
| `./luna.config.json` | Project-local overrides |

```json
{
  "config_dir": "./luna.d",
  "approval": {
    "store": "./luna.d/approvals.db",
    "ttl": "10m",
    "provider": "fake"
  },
  "cli": {
    "approver_users": ["1000"]
  },
  "telegram": {
    "bot_token_file": "/path/to/token",
    "approver_user_id": "123456789",
    "chat_id": ""
  },
  "audit": {
    "file": "./luna.d/audit.jsonl"
  }
}
```

## Core settings (SQLite + TTL)

| JSON field | Environment override | Default | Purpose |
| ---------- | -------------------- | ------- | ------- |
| `approval.store` | `LUNA_APPROVAL_STORE` | `approvals.db` | SQLite database path |
| `approval.ttl` | `LUNA_APPROVAL_TTL` | `5m` | Pending `approval_id` lifetime |

**Example (env overrides file):**

```bash
export LUNA_APPROVAL_STORE="$HOME/.config/luna/approvals.db"
export LUNA_APPROVAL_TTL=15m
```

`luna serve` opens the store at startup. If the path is missing, SQLite creates
the file on first write.

---

## Notification providers

| JSON field | Environment override | Default | Purpose |
| ---------- | -------------------- | ------- | ------- |
| `approval.provider` | `LUNA_APPROVAL_PROVIDER` | `fake` | `fake`, `telegram`, or `fake,telegram` |

| Provider | Behavior |
| -------- | -------- |
| *(unset)* | Same as `fake` — no external notification |
| `fake` | Records pending approvals only; operator uses CLI |
| `telegram` | Sends Approve/Deny inline keyboard (requires Telegram env below) |
| `fake,telegram` | Both |

```bash
export LUNA_APPROVAL_PROVIDER=telegram
```

---

## CLI approve / deny

### Commands

```bash
luna-interceptor approvals list
luna-interceptor approvals show <id>
luna-interceptor approvals approve <id>
luna-interceptor approvals deny <id>
```

(`luna approvals …` is equivalent when using the Cobra binary name.)

### Who may approve

| JSON field | Environment override | Purpose |
| ---------- | -------------------- | ------- |
| `cli.approver_users` | `LUNA_CLI_APPROVER_USERS` | Unix numeric uids allowed to run `approve` / `deny` |

**Required** for CLI approve. If unset or your uid is not listed, approve fails.

```bash
export LUNA_CLI_APPROVER_USERS="$(id -u)"
# multiple operators:
export LUNA_CLI_APPROVER_USERS="1000,1001"
```

---

## Telegram provider (optional)

Enable in the provider list:

```bash
export LUNA_APPROVAL_PROVIDER=telegram
```

### Environment

| JSON field | Environment override | Required | Purpose |
| ---------- | -------------------- | -------- | ------- |
| `telegram.bot_token` | `LUNA_TELEGRAM_BOT_TOKEN` | One of token paths | Inline bot token |
| `telegram.bot_token_file` | `LUNA_TELEGRAM_BOT_TOKEN_FILE` | One of token paths | Path to token file |
| `telegram.approver_user_id` | `LUNA_TELEGRAM_APPROVER_USER_ID` | Yes | Sole authorized approver |
| `telegram.chat_id` | `LUNA_TELEGRAM_CHAT_ID` | No | Defaults to approver user id |

**Example:**

```bash
export LUNA_TELEGRAM_BOT_TOKEN_FILE="$HOME/.config/luna/telegram-bot-token"
export LUNA_TELEGRAM_APPROVER_USER_ID=123456789
# optional:
export LUNA_TELEGRAM_CHAT_ID=-1001234567890
```

### Callback delivery

Inline Approve/Deny buttons require something to receive Telegram
`callback_query` updates:

| Workflow | Who polls |
| -------- | --------- |
| `luna exec` (default wait) | Started automatically while waiting |
| MCP `serve` / agents | Run in another terminal: `luna telegram poll` |
| Manual | `luna approvals approve <approval_id>` (no Telegram buttons) |

```bash
luna telegram poll
```

Callback payload format: `approve:<approval_id>` and `deny:<approval_id>`.

---

## Full example: OpenCode + CLI approvals

`opencode.json` starts the interceptor; set env in your shell or a wrapper script.

**1. Policy + approval paths**

```bash
mkdir -p "$HOME/.config/luna"
cp examples/luna.d/policy.yml "$HOME/.config/luna/"
# optional:
cp examples/luna.d/hosts.yml "$HOME/.config/luna/"
```

**2. JSON config** — copy [examples/luna.config.json](../examples/luna.config.json) to `./luna.config.json` or `~/.config/luna/config.json`.

**3. Optional env overrides** (see [examples/luna.d/env.example](../examples/luna.d/env.example)):

```bash
export LUNA_CLI_APPROVER_USERS="$(id -u)"   # overrides cli.approver_users in JSON
```

**3. Run OpenCode** from a directory where config resolves, or rely on `LUNA_CONFIG_DIR`.

**4. When the agent hits `PERMISSION_REQUIRED`:**

```bash
luna-interceptor approvals list
luna-interceptor approvals approve <approval_id>
```

Tell the agent to retry with the same host, command, timeout, and `approval_id`.

---

## Agent / MCP contract (not env config)

| Step | Action |
| ---- | ------ |
| First call | `execute_remote` without `approval_id`, or `luna exec --no-wait` on a mutating command |
| Response | `PERMISSION_REQUIRED:` + structured fields |
| Human | Approves via CLI or Telegram |
| Retry | Same `host`, `command`, `timeout_sec`, plus `approval_id` (CLI: `luna exec` waits by default; `--approval-id` / `--no-wait` for non-blocking) |

There is no environment variable that lets the agent bypass approval.

---

## Policy vs approval

| Concern | Configured by |
| ------- | ------------- |
| Is this command read-only, mutating, or forbidden? | `policy.yml` + compiled engine |
| Policy directory | `config_dir` / `LUNA_CONFIG_DIR` / `./luna.d` fallbacks |
| Where are pending approvals stored? | `approval.store` / `LUNA_APPROVAL_STORE` |
| How long is an `approval_id` valid? | `approval.ttl` / `LUNA_APPROVAL_TTL` |
| How is the human notified? | `approval.provider` / `LUNA_APPROVAL_PROVIDER` |
| Who may run CLI approve? | `cli.approver_users` / `LUNA_CLI_APPROVER_USERS` |

---

## Troubleshooting

| Symptom | Check |
| ------- | ----- |
| `serve` starts but every mutation fails immediately | `LUNA_APPROVAL_STORE` writable; SQLite not locked by another process |
| CLI `approve` forbidden | `LUNA_CLI_APPROVER_USERS` includes your `id -u` |
| Retry still `PERMISSION_REQUIRED` | Same host/command/timeout; id not expired; not already consumed |
| Telegram message never arrives | `LUNA_APPROVAL_PROVIDER` includes `telegram`; token and chat id correct |
| Telegram buttons do nothing | No poller/webhook running — use CLI approve |
