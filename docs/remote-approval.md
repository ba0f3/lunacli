# Remote human approval (operators)

> **Canonical OOB configuration guide:** [oob-approval.md](oob-approval.md)  
> Approval is **always** out-of-band via Telegram while `luna serve` runs.

This page summarizes Telegram setup; full variable reference and examples are in
[oob-approval.md](oob-approval.md).

## Quick reference

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `LUNA_APPROVAL_TTL` | `5m` | Pending approval lifetime (in-memory while serve runs) |

Approvals are held in process memory only; restarting `luna serve` clears pending items.

## Telegram

| Variable | Required | Meaning |
| -------- | -------- | ------- |
| `LUNA_TELEGRAM_BOT_TOKEN` or `LUNA_TELEGRAM_BOT_TOKEN_FILE` | Yes (one of) | Bot token |
| `LUNA_TELEGRAM_APPROVER_USER_ID` | Yes | Sole authorized approver (numeric user id) |
| `LUNA_TELEGRAM_CHAT_ID` | No | Defaults to approver id; set for group/channel |

```bash
export LUNA_TELEGRAM_BOT_TOKEN_FILE="$HOME/.config/luna/telegram-bot-token"
export LUNA_TELEGRAM_APPROVER_USER_ID=123456789
```

Inline keyboards use `approve:<approval_id>` / `deny:<approval_id>`. `luna serve`
runs a background `getUpdates` poller; approve via Telegram only (no CLI approve path).
