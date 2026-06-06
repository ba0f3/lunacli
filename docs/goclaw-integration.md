# Goclaw and `luna-interceptor` integration

This guide describes how to run **goclaw** (or any similar MCP client) with `luna-interceptor` using **local stdio**, with **`LUNA_APPROVAL_MODE=remote`** so mutations require **out-of-band human approval** instead of trusting `allow_mutations` from the agent.

For interceptor configuration (approval store, Telegram, CLI fallback), see [`docs/remote-approval.md`](remote-approval.md). For background and threat model, see [`docs/superpowers/specs/2026-05-16-remote-human-approval-design.md`](superpowers/specs/2026-05-16-remote-human-approval-design.md).

## Architecture

- **goclaw** and **`luna-interceptor`** run on the **same machine**.
- They communicate over **stdio only** (MCP JSON-RPC on the interceptor’s stdin/stdout). The interceptor must **not** expose a public HTTP API for tool execution.
- The interceptor talks to **remote Linux hosts** over SSH/SFTP using its own process identity. With default `transport.mode: proxy`, credentials come from **luna-proxy signing** (in-process luna-sdk); lunacli still **dials hosts directly** — the proxy does not carry SSH traffic. Signed keys stay in the interceptor process, not in the goclaw client.

```text
goclaw process
  |
  | MCP stdio (local pipe or PTY)
  v
luna-interceptor
  |
  | SSH / SFTP
  v
managed hosts

luna-interceptor
  |
  | approval providers (Telegram, local CLI, …)
  v
human approver
```

## Enable remote approval mode

Set environment variables **for the interceptor process** before spawning it (see [`docs/remote-approval.md`](remote-approval.md) for full examples):

```text
LUNA_APPROVAL_MODE=remote
LUNA_APPROVAL_STORE=/var/lib/luna-interceptor/approvals.db
LUNA_APPROVAL_TTL=5m
```

Legacy OpenCode-style workflows use **`LUNA_APPROVAL_MODE=local`** (default), where **`allow_mutations=true`** is honored after explicit in-chat approval.

## `approval_id` retry flow

For **mutating** `execute_remote` calls in **remote** mode:

1. **First call** — same parameters you intend to run (`host`, `command`, `timeout_sec`, …). Do **not** treat `allow_mutations=true` as authority; it is **not** trusted for mutations in remote mode.
2. **Response** — `PERMISSION_REQUIRED:` plus structured fields:
   - **`approval_id`** — stable ID for this pending request  
   - **`expires_at`** — RFC3339 UTC time after which the ID is invalid  
   - **`fingerprint_prefix`** — short verifier prefix for the human (full fingerprint is server-side)
3. **Human** — approves or denies **out of band** (Telegram, `luna-interceptor approvals …`, etc.).
4. **Retry** — call **`execute_remote` again with the exact same `host`, `command`, and `timeout_sec`**, and set **`approval_id`** to the returned ID.

Rules:

- Any change to `command`, `host`, or timeout invalidates the approval (verification fails closed).
- Each approval is **single-use**: after a successful mutating run, the same `approval_id` must not execute again.
- If approval **expires**, create a **new** pending request with another mutating call (no `approval_id`).

Read-only commands **do not** go through this flow; they execute immediately.

## Instructions and skills are policy material only

Reuse Luna’s **`instructions/`** and **skills** in goclaw as **documentation and behavioral hints** for the model.

They are **not** a security boundary: **goclaw is not trusted** to approve mutations. Only the interceptor’s **classification**, **approval store**, and **configured human approver** authorize mutating execution in remote mode.

## SSH agent and key isolation

Goal: keep **private keys** and **`SSH_AUTH_SOCK`** away from the agent process.

Recommended practices:

- Run **`luna-interceptor`** under a **dedicated Unix account** that owns SSH access to managed hosts.
- Run **goclaw** as a **different user** without read access to `~/.ssh` private keys or the interceptor’s agent socket.
- Point **`SSH_AUTH_SOCK`** (and `~/.ssh` for the interceptor user) **only** at the interceptor’s environment — not at goclaw’s.
- Prefer a **restricted role account key** for Luna, **not** your personal daily-driver key.
- Keep **`~/.ssh`** permissions tight (`0700` dir, `0600` keys), **`known_hosts` pinned**, and **avoid agent forwarding** unless you fully understand the blast radius.

See also [`README.md`](../README.md) (SSH client compatibility) and the design spec **SSH Key Protection** section.
