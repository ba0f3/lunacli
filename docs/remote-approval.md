# Remote human approval (operators)

> **Canonical OOB configuration guide:** [oob-approval.md](oob-approval.md)  
> After the zero-trust redesign, approval is **always** out-of-band.  
> `LUNA_APPROVAL_MODE` and `allow_mutations` are **removed**.

This page summarizes Telegram setup; full variable reference and examples are in
[oob-approval.md](oob-approval.md).

## Quick reference

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `LUNA_APPROVAL_STORE` | `approvals.db` | SQLite approvals database |
| `LUNA_APPROVAL_TTL` | `5m` | Pending approval lifetime |
| `LUNA_APPROVAL_PROVIDER` | `fake` | `fake`, `telegram`, or `fake,telegram` |
| `LUNA_CLI_APPROVER_USERS` | *(required for CLI approve)* | Comma-separated Unix uids |

```bash
luna-interceptor approvals list
luna-interceptor approvals approve <id>
luna-interceptor approvals deny <id>
```

## Telegram

| Variable | Required | Meaning |
| -------- | -------- | ------- |
| `LUNA_TELEGRAM_BOT_TOKEN` or `LUNA_TELEGRAM_BOT_TOKEN_FILE` | Yes (one of) | Bot token |
| `LUNA_TELEGRAM_APPROVER_USER_ID` | Yes | Sole authorized approver (numeric user id) |
| `LUNA_TELEGRAM_CHAT_ID` | No | Defaults to approver id; set for group/channel |

```bash
export LUNA_APPROVAL_PROVIDER=telegram
export LUNA_TELEGRAM_BOT_TOKEN_FILE="$HOME/.config/luna/telegram-bot-token"
export LUNA_TELEGRAM_APPROVER_USER_ID=123456789
```

Inline keyboards use `approve:<approval_id>` / `deny:<approval_id>`. The MCP
server does not receive webhooks; run CLI approve or a separate `getUpdates`
poller until one ships in-tree.

See [oob-approval.md](oob-approval.md) for OpenCode integration and troubleshooting.
