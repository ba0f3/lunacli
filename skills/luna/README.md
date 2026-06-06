# Luna agent skill

Portable skill for AI agents that use **lunacli** MCP for remote SSH execution.

## Quick install

```bash
git clone https://github.com/ba0f3/lunacli.git
cp -r lunacli/skills/luna ~/.agents/skills/luna   # adjust path for your agent
```

Or download only this folder from the repo and place it at `skills/luna` in your agent's skill search path.

## MCP server

Configure your client to run:

```json
["/path/to/luna", "serve"]
```

Set `cwd` to the directory containing `luna.config.json` (or use user-wide `~/.config/luna/` after `luna onboard`).

See [SKILL.md](./SKILL.md) for tool usage, approval flow, and error handling.

## Operator docs

- [lunacli README](../../README.md)
- [Out-of-band approval](../../docs/oob-approval.md)
