---
name: luna
description: >-
  Use luna MCP tools for secure remote Linux SSH execution. Invoke when the
  user asks to run commands, read files, or inspect hosts remotely; when lunacli
  or luna serve is configured; or when MCP tools execute_remote, list_hosts,
  read_file, fetch_remote_file, or scan_host_inventory are available. Never use
  raw ssh/scp for managed hosts when luna MCP is present.
---

# Luna — remote SSH via MCP

Luna (`lunacli`) is a **stdio MCP server** that executes SSH on your behalf with **command classification** and **human approval** for mutating operations. The agent must use Luna MCP tools — not shell `ssh`, `scp`, or `rsync` — for managed hosts.

## Install this skill

Copy or symlink this folder into your agent's skills directory:

```bash
# Example: from lunacli repo root
mkdir -p ~/.agents/skills   # or ~/.cursor/skills, .claude/skills, etc.
cp -r skills/luna ~/.agents/skills/luna
```

Point your MCP client at Luna:

```json
{
  "mcpServers": {
    "luna": {
      "command": "/absolute/path/to/luna",
      "args": ["serve"],
      "cwd": "/path/to/project-or-home-with-luna.config.json"
    }
  }
}
```

Operator setup (once per machine): `luna onboard` → writes `luna.config.json`, `policy.yml`, Telegram approval, and optional luna-proxy transport.

## Hard rules

1. **Use MCP tools only** for remote work when Luna is connected. Do not run `ssh`, `scp`, `rsync`, or `curl` against managed hosts to bypass policy.
2. **Do not invent approval.** Mutating commands require a human approver (Telegram by default). You cannot self-approve.
3. **Call `list_hosts` first** when the target host is unknown. Hosts come from `~/.ssh/known_hosts` and `hosts.yml` entries with `host_key`.
4. **Unknown host keys** — on first connect to an untrusted host, Luna blocks and sends a **TRUST HOST** Telegram prompt (when `luna serve` is running). Approve there to add the host to `hosts.yml`. On an interactive terminal, `luna ssh-debug <host>` can prompt locally instead.
5. **Prefer read-only tools** before mutating: `read_file`, `scan_host_inventory`, read-only `execute_remote` (`cat`, `grep`, `systemctl status`, etc.).
6. **One command per `execute_remote` call.** Do not chain mutating operations to evade classification.
7. **Respect timeouts.** Default `timeout_sec` is 30 (max 300). Increase for long-running read-only diagnostics only when needed.

## Tool reference

| Tool | Purpose | Approval |
|------|---------|------------|
| `list_hosts` | Discover dialable host aliases | No |
| `execute_remote` | Run a shell command | Read-only: no. Mutating: human OOB |
| `read_file` | Read remote file via SFTP (size cap) | No |
| `fetch_remote_file` | Download remote file via SFTP | No |
| `scan_host_inventory` | OS, packages, services, ports scan | No |
| `lookup_cve` | Local CVE database search | No |

### Host format

All host parameters: `[user@]hostname[:port]`

Examples: `web1`, `root@10.0.0.5`, `ubuntu@192.168.1.50:2222`

Luna resolves `User` and `Port` from `~/.ssh/config` when omitted.

## Recommended workflow

```
1. list_hosts                          → pick target alias
2. read-only execute_remote / read_file → gather state
3. execute_remote (mutating)           → blocks until human approves
4. read-only verify                    → confirm result
```

For broad discovery on one machine, `scan_host_inventory` before ad-hoc commands.

## execute_remote — approval behavior

**Read-only commands** (per `policy.yml` + engine): run immediately; result includes `Class: read-only`.

**Mutating commands**: Luna creates a pending approval and **blocks the MCP call** until the human approves, denies, or the approval TTL expires. You do not need to poll manually on the first call — wait for the tool to return.

**If the wait is interrupted** (client timeout, cancelled context), the response includes `approval_id`. Retry with the **exact same** `host`, `command`, `timeout_sec`, plus that `approval_id` to resume waiting after the human approves on Telegram.

Changing any of host, command, or timeout invalidates the approval.

### Response fields (success)

```
Host:     ...
Command:  ...
Class:    read-only | mutating
Exit:     0
Duration: ...

--- STDOUT ---
...
--- STDERR ---
...
```

Non-zero `Exit` is a normal command failure, not an MCP error. Inspect stderr before retrying.

## Error handling

| Prefix | Meaning | Agent action |
|--------|---------|--------------|
| `BLOCKED:` | Permanently forbidden (forbidden patterns or policy) | Stop. Do not rephrase or obfuscate the command. Tell the user why. |
| `PERMISSION_REQUIRED:` | Approval denied, expired, invalid, or wait ended | If `approval_id` present and human may still approve, retry with same args + `approval_id`. Otherwise explain to user and propose a read-only alternative. |
| `ACCESS_REQUIRED:` | luna-proxy access not yet approved (transport.mode proxy) | Tell user to approve on **proxy** Telegram, then retry the same call. |
| `ACCESS_DENIED:` | Proxy denied access | Stop. Do not retry blindly. |
| `ACCESS_EXPIRED:` | Signed credential expired | Retry; user re-approves on proxy. |
| `SSH execution error:` | Dial/auth/session failure | Check host alias, known_hosts, hosts.yml host_key, proxy/certs. If host is new, approve **TRUST HOST** in Telegram. Do not switch to raw ssh. |

**Never** treat `PERMISSION_REQUIRED` as "ask the user in chat to type yes" — Luna requires **out-of-band** approval (Telegram). Inform the user that a Telegram prompt was sent.

## Command hygiene

- Use explicit paths and flags; avoid shell tricks (`$(...)`, obfuscated `$'\x'`, redirects to sensitive paths).
- Redirects to `/dev/null` for read-only diagnostics are allowed by the engine.
- `sudo`, destructive `rm`, reverse shells, and similar patterns are **BLOCKED** regardless of policy.
- For file content, prefer `read_file` over `execute_remote cat` when possible (SFTP, size limits).

## Transport notes (operator)

Default `transport.mode` is **proxy**: SSH credentials come from **luna-proxy** after proxy-side access approval (separate Telegram from command approval). Agent sees `ACCESS_*` errors when proxy access is pending.

`transport.mode: direct` uses local ssh-agent/disk keys — weaker; only when operator explicitly configured it.

## What to tell the user

When a mutating command is submitted:

> "This command requires human approval. A Telegram notification was sent. I'll wait for approval and continue when Luna returns the result."

When blocked:

> "Luna classified this command as forbidden and will not run it: \<reason\>. I can suggest a read-only alternative."

## Anti-patterns

- Running the same mutating command repeatedly without approval
- Splitting one mutating action into many small mutating commands
- Using `allow_mutations` or similar client flags (not honored for mutations)
- Bypassing Luna with terminal ssh because MCP returned an error
- Guessing hostnames instead of calling `list_hosts`

## Infrastructure Learning Protocol

Luna automatically maintains `data/infrastructure/` when conversations or tool
results reveal infrastructure facts.

### Knowledge Base Rules

- Store structured facts as YAML and human notes as Markdown.
- Record provenance for every fact: source type, timestamp, evidence, and confidence.
- Prefer fresh `scan_host_inventory` evidence over older conversation-derived facts.
- Treat explicit user statements as useful but low-confidence until confirmed by scan or Wazuh evidence.
- Never store credentials, private keys, passwords, tokens, session cookies, or secret values.
- Redact secret-like process arguments before writing command lines.
- Keep Wazuh evidence separate from direct host scan evidence.

### Inventory Scan Workflow

When asked to learn, scan, inventory, or document servers:

1. Call `list_hosts`.
2. Select requested hosts, or ask for scope if the user request is ambiguous.
3. Call `scan_host_inventory` once per selected host.
4. Write scan evidence under `data/infrastructure/scans/<timestamp>/`.
5. Update `data/infrastructure/hosts/<host-id>/` with host, package, service, process, port, container, and vulnerability files.
6. Update `data/infrastructure/software/<software-id>.yaml` cross-references.
7. Update `data/infrastructure/index.md`.
8. Report what was learned, which collectors failed, confidence level, and recommended next checks.
