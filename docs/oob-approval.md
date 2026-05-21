# Out-of-band (OOB) approval configuration

Human approval for mutating `execute_remote` commands via **`luna serve`** (stdio MCP).

**Related:** [zero-trust-interceptor.md](zero-trust-interceptor.md), [examples/luna.d/env.example](../examples/luna.d/env.example)

Approvals are held **in the MCP server process memory** (not SQLite). Restarting `luna serve` clears all pending approvals. Approval is **Telegram-only** (inline Approve/Deny buttons).

### Configuration precedence (lowest → highest)

1. `~/.config/luna/config.json`
2. `./luna.config.json`
3. Environment variables (`LUNA_*`)

Example: [examples/luna.config.json](../examples/luna.config.json)

**MCP client command** must include the subcommand:

```json
"command": ["/path/to/luna", "serve"]
```

Plain `luna` prints usage and does not start the server.

---

## How it works

1. Agent calls `execute_remote` on a **mutating** command (per `policy.yml`).
2. Server stores a pending approval in memory and sends a Telegram message with buttons.
3. Server returns `PERMISSION_REQUIRED` with `approval_id`, `expires_at`, and `fingerprint_prefix`.
4. Human taps **Approve** or **Deny** in Telegram (poll loop runs inside `luna serve`).
5. Agent retries `execute_remote` with the **same** `host`, `command`, `timeout_sec`, and `approval_id`.
6. Gate verifies and **consumes** the approval, then SSH runs.

Read-only commands skip this flow.

**One process:** A second `luna serve` instance has separate memory; pending IDs are not shared.

---

## JSON config (required fields)

```json
{
  "config_dir": "./luna.d",
  "approval": {
    "ttl": "10m"
  },
  "telegram": {
    "bot_token_file": "/path/to/telegram-bot-token",
    "approver_user_id": "123456789",
    "chat_id": "123456789"
  }
}
```

| JSON field | Environment override | Default | Purpose |
| ---------- | -------------------- | ------- | ------- |
| `approval.ttl` | `LUNA_APPROVAL_TTL` | `5m` | Pending `approval_id` lifetime |
| `telegram.bot_token_file` | `LUNA_TELEGRAM_BOT_TOKEN_FILE` | — | **Required** for serve |
| `telegram.approver_user_id` | `LUNA_TELEGRAM_APPROVER_USER_ID` | — | Sole authorized approver |
| `telegram.chat_id` | `LUNA_TELEGRAM_CHAT_ID` | approver user id | Chat for notifications |

**Not used:** SQLite approval DB, CLI approve commands, or `approval.provider` — serve keeps pending approvals in memory and uses Telegram only.

---

## Telegram setup

1. Create a bot via [@BotFather](https://t.me/BotFather); save token to `bot_token_file` (mode `0600`).
2. Send `/start` to the bot from your Telegram account.
3. Set `approver_user_id` to your numeric Telegram user id.
4. Run `luna serve`; stderr logs server start. Poll loop handles button callbacks.

Callbacks use `approve:<approval_id>` / `deny:<approval_id>`. The server edits the Telegram message to show the final status.

---

## Agent retry example

First call (mutating):

```
PERMISSION_REQUIRED: ...

approval_id: 7e651d19-...
expires_at: 2026-05-21T17:06:02Z
```

After human approves in Telegram, retry with identical parameters plus `approval_id`.

---

## Troubleshooting

| Symptom | Check |
| ------- | ----- |
| `approval: telegram required` on serve | `telegram.bot_token_file` and `approver_user_id` |
| Buttons do nothing | Same `luna serve` process still running; token valid |
| `approval_id` invalid after restart | Expected — request approval again |
| OpenCode still uses `luna` only | Change to `["luna", "serve"]` |
