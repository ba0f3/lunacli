# Example Luna configuration (`luna.d`)

Starter **`policy.yml`** and **`hosts.yml`** for the zero-trust interceptor.

## Install

Pick one config directory (see [zero-trust-interceptor.md](../../docs/zero-trust-interceptor.md)):

```bash
# Project-local (typical for development)
mkdir -p luna.d
cp policy.yml hosts.yml ../../luna.d/

# Or user-wide
mkdir -p ~/.config/luna
cp policy.yml hosts.yml ~/.config/luna/
```

Edit `hosts.yml` so `host` values match your SSH targets and are present in
`~/.ssh/known_hosts`.

## Validate

```bash
# From repository root (after: cp examples/luna.d/*.yml ./luna.d/)
cd interceptor && make build
../bin/luna-interceptor exec ubuntu@your-host uptime

# Or point at examples without copying:
LUNA_CONFIG_DIR="$(pwd)/../examples/luna.d" ../bin/luna-interceptor serve
```

`exec` runs read-only commands immediately. Mutating commands create a pending
approval (Telegram, CLI, etc.), **wait** until you approve or deny, then run.
Use `--no-wait` to exit with `PERMISSION_REQUIRED` (MCP-style retry with
`--approval-id`). MCP `execute_remote` always uses the non-blocking retry flow.

## Files

| File | Required | Purpose |
| ---- | -------- | ------- |
| `policy.yml` | **Yes** for `serve` | Command classification rules |
| `hosts.yml` | No | Inventory aliases, tags, descriptions |
| `env.example` | No | Optional env overrides — see [oob-approval.md](../../docs/oob-approval.md) |

Project-level JSON (approval, `config_dir`): copy [../luna.config.json](../luna.config.json) to `./luna.config.json`.

Customize rules before production use — the examples are a **baseline**, not a
complete production policy.
