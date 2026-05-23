# Example Luna configuration (`luna.d`)

Starter **`policy.yml`** and **`hosts.yml`** for the zero-trust interceptor.

## Install

Run `luna onboard` for interactive setup, or copy manually.

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
make build
LUNA_CONFIG_DIR="$(pwd)/luna.d" ./bin/luna serve
```

Configure Telegram in `luna.config.json` (see [oob-approval.md](../../docs/oob-approval.md)). Point your MCP client at `["/path/to/luna", "serve"]`.

Mutating `execute_remote` calls return `PERMISSION_REQUIRED` until you approve via Telegram, then retry with `approval_id`.

## Files

| File | Required | Purpose |
| ---- | -------- | ------- |
| `policy.yml` | **Yes** for `serve` | Command classification rules |
| `hosts.yml` | No | Inventory aliases, tags, descriptions |
| `env.example` | No | Optional env overrides — see [oob-approval.md](../../docs/oob-approval.md) |

Project-level JSON: copy [../luna.config.json](../luna.config.json) to `./luna.config.json`.

Customize rules before production use — the examples are a **baseline**, not a
complete production policy.
