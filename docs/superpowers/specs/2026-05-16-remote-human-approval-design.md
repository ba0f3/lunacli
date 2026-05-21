# Remote Human Approval for Goclaw — Design Spec

**Date:** 2026-05-16
**Status:** Approved design
**Scope:** Luna interceptor remote approval mode, goclaw local-stdio integration, approval provider abstraction, SSH key exposure controls

## Summary

Add a remote human approval model for using `luna-interceptor` with goclaw, an OpenClaw port that runs separately from OpenCode. goclaw should reuse Luna's skills and instructions as policy material, but it must not be trusted to approve mutations. The interceptor remains the policy and execution boundary: it classifies commands, creates pending approval requests, verifies out-of-band human approvals, executes approved mutations exactly once, and protects SSH key access.

Phase 1 uses local-only stdio between goclaw and the interceptor, command-by-command approval, a provider abstraction for approval transports, Telegram as the first remote provider, and a local CLI fallback. This design is for interactive human-plus-AI operations, not CI/CD automation.

## Goals

1. Let a human approve mutating agent requests remotely.
2. Keep goclaw local to the interceptor over stdio; do not expose a network API for the interceptor.
3. Remove `allow_mutations=true` as an authority signal in remote approval mode.
4. Require command-by-command approvals tied to an exact request fingerprint.
5. Keep SSH keys and `SSH_AUTH_SOCK` out of goclaw's reach where practical.
6. Keep the approval transport pluggable so Telegram is not hard-coded into the core policy.
7. Preserve existing OpenCode/local workflows during phase 1 through an explicit legacy/local mode.

## Non-Goals

- CI/CD deployment automation.
- Approval windows such as "approve all mutations for 10 minutes".
- Team approval or quorum workflows.
- Browser admin UI.
- Network-exposed interceptor API.
- Automatic mutation approval based on command pattern.
- Replacing SSH host hardening or remote operating-system access controls.

## Deployment Model

goclaw and `luna-interceptor` run on the same remote server.

```text
goclaw process
  |
  | local stdio MCP
  v
luna-interceptor
  |
  | SSH / SFTP
  v
remote Linux hosts

luna-interceptor
  |
  | approval provider interface
  v
Telegram bot / local CLI / future providers
```

The interceptor is local-only from goclaw's perspective. It should not open a public HTTP listener for tool execution. If a future approval provider requires inbound callbacks, that callback endpoint belongs to the provider component, not to the tool execution interface.

## Trust Boundaries

- goclaw is not trusted to approve mutations.
- goclaw can request tools over local stdio only.
- `luna-interceptor` owns command classification, pending approval creation, approval verification, SSH execution, and audit logging.
- Approval providers are human interaction transports, not sources of policy.
- The configured human approver identity is the authority for remote approval decisions.
- SSH private keys are never exposed to prompts, goclaw messages, or approval provider payloads.

## Approval Modes

### Legacy Local Mode

Existing OpenCode workflows can continue using `allow_mutations=true` after explicit in-chat human approval.

This mode is intended for local/trusted interactive use only.

### Remote Approval Mode

Remote approval mode is for goclaw and any other runtime where the agent process cannot be trusted to self-assert approval.

Rules:

- `allow_mutations=true` is ignored or rejected as an authority signal.
- Mutating tool calls without a valid `approval_id` create a pending approval request and return `PERMISSION_REQUIRED`.
- Mutating tool calls with a valid `approval_id` execute only if the approval record exactly matches the request.
- Approved requests execute once, then become consumed.
- Denied, expired, consumed, or mismatched approval records never execute.

## Command Flow

1. goclaw calls `execute_remote` or another mutating-capable tool.
2. The interceptor classifies the request.
3. Read-only requests execute immediately.
4. Mutating requests without `approval_id` create a pending approval record.
5. The interceptor sends the request to configured approval providers.
6. The tool response returns `PERMISSION_REQUIRED` with the approval ID, expiry, and fingerprint.
7. The human approves or denies out of band.
8. goclaw retries the exact same request with `approval_id`.
9. The interceptor verifies the request fingerprint, status, approver identity, expiry, and single-use state.
10. If valid, the interceptor executes the mutation and marks the approval consumed.

## Approval Request Model

Each pending approval record contains:

- approval ID
- tool name
- host
- redacted command or transfer target
- normalized, redacted request body
- classification and reason
- timeout
- request timestamp
- expiry timestamp
- SHA-256 fingerprint over stable, redacted request fields
- status: pending, approved, denied, expired, consumed
- approval provider decision metadata
- approver identity when decided
- audit timestamps
- redaction metadata (redaction algorithm/version used)

**Mandatory Secret Redaction:** A deterministic redaction step (e.g., `redactSecrets()`) MUST run before any approval or audit persistence. Fields like "command", "transfer target", and "normalized request body" must only be stored in their redacted form.
The SHA-256 fingerprint must be computed from a defined canonical representation of the *redacted* request (e.g., `computeFingerprint(canonicalize(redactedRequest))`) so the fingerprint itself cannot leak secrets via brute force or rainbow table attacks. All state transitions and audit events must reference the redacted fields.

The fingerprint must be computed by the interceptor. goclaw cannot supply its own fingerprint.

## Approval Provider Abstraction

Core policy depends on an interface, not on Telegram directly.

Provider responsibilities:

- Send approval request to the human.
- Receive approve/deny action.
- Return provider identity metadata.
- Avoid leaking secrets beyond the minimum needed for human review.
- Report delivery or callback errors.

Initial providers:

- Telegram provider with inline keyboard buttons.
- Local CLI provider for fallback or emergency local approval.

Future providers:

- Discord
- Slack
- email
- webhook
- mobile push

Adding a provider must not change approval matching, request fingerprints, or SSH execution policy.

## Telegram Provider

Telegram is the phase-1 remote approval provider.

Configuration:

- bot token from environment or config file outside the repo
- allowed Telegram user ID
- optional allowed chat ID
- request expiry duration

Message content:

- host
- tool
- command or target path
- classification reason
- expiry time
- approval ID
- fingerprint prefix
- Approve and Deny inline buttons

Security rules:

- Callback `user_id` must match the configured approver.
- Callback data must contain an opaque approval ID and action, not the full command.
- Unauthorized callbacks are denied and audited.
- Expired requests cannot be approved.
- Telegram delivery failure does not permit execution.

## Local CLI Fallback

The local CLI fallback is for situations where Telegram is unavailable.

Expected commands:

```bash
luna-interceptor approvals list
luna-interceptor approvals show <approval-id>
luna-interceptor approvals approve <approval-id>
luna-interceptor approvals deny <approval-id>
```

The CLI uses the same approval store and same single-use semantics as remote providers. It does not bypass request fingerprint matching.

**Explicit Authorization:** The CLI handlers for `approve` and `deny` must explicitly authorize the executing user. They must check that the OS principal running the command maps to a configured approver identity. Unauthorized attempts must be rejected with an error, and an audit event must be emitted detailing the principal identity, command, approval-id, timestamp, and outcome.

## Approval Store And Audit Log

Recommended phase-1 store: local SQLite database or a strictly permissioned JSONL store.

Requirements:

- owned by the interceptor service account
- file mode `0600`
- durable across short interceptor restarts
- records all state transitions
- fail closed if unavailable or corrupt

Audit entries:

- request created
- provider notification attempted
- provider notification failed
- approved
- denied
- expired
- consumed
- execution result summary
- mismatch rejection
- unauthorized approval attempt

Secrets should be redacted from audit logs where possible, but the human approval prompt must retain enough command detail to make a real decision.

## SSH Key Protection

The goal is to let a human remotely approve AI-agent mutations while keeping SSH keys out of the agent's reach.

Recommended model:

- Do not give goclaw direct access to SSH keys.
- Run `luna-interceptor` as the only process that can reach `SSH_AUTH_SOCK` or key files.
- Run goclaw and the interceptor as separate Unix users if practical.
- Use a dedicated SSH key for Luna instead of a personal key.
- Keep the key passphrase-protected.
- Load the key into `ssh-agent` manually or through a secure service startup flow.
- Restrict `SSH_AUTH_SOCK` permissions so only the interceptor user can use the agent.
- Keep `~/.ssh` permissions strict: directory `0700`, private keys `0600`, known hosts `0644`.
- Keep known_hosts pinned and strict host key checking enabled.
- Do not use agent forwarding.
- Prefer a key limited to the hosts administered through Luna.

Host-level privilege controls such as narrow `sudoers` rules are optional hardening, not a phase-1 requirement.

## Error Handling

- If an approval provider is unavailable, mutating commands remain blocked unless another configured provider approves the request.
- If the approval store is unavailable or corrupt, mutating commands fail closed.
- If goclaw retries with a changed command, the approval is rejected.
- If the approval expires, the command must be requested again.
- If the interceptor restarts, pending approvals are loaded from the approval store if the store is healthy.
- If approval callback handling fails, the request remains pending until expiry.
- If execution succeeds or fails after valid approval, the approval is consumed.

## Configuration

Remote approval mode should be explicit.

Example environment:

```text
LUNA_APPROVAL_MODE=remote
LUNA_APPROVAL_STORE=/var/lib/luna-interceptor/approvals.db
LUNA_APPROVAL_TTL=5m
LUNA_APPROVAL_PROVIDER=telegram,local-cli
LUNA_TELEGRAM_BOT_TOKEN_FILE=/etc/luna/telegram-bot-token
LUNA_TELEGRAM_APPROVER_USER_ID=123456789
LUNA_TELEGRAM_CHAT_ID=123456789
SSH_AUTH_SOCK=/run/luna-interceptor/ssh-agent.sock
```

Legacy local mode remains explicit or default for existing OpenCode behavior:

```text
LUNA_APPROVAL_MODE=local
```

## MCP Tool Surface Changes

`execute_remote`:

- keep `allow_mutations` for legacy local mode
- add optional `approval_id`
- in remote mode, reject `allow_mutations=true` without a valid matching approval

`transfer_file`:

- keep existing legacy local behavior
- add optional `approval_id`
- in remote mode, require valid matching approval before upload

Potential new MCP tools:

- `list_pending_approvals`
- `get_approval_status`

These are optional convenience tools. Core security must not depend on the agent honestly polling status.

## Testing Plan

Unit tests:

- read-only command executes without approval
- mutating command creates pending approval in remote mode
- `allow_mutations=true` is rejected in remote mode
- valid approval ID permits exact command once
- reused approval ID is rejected
- changed command with approved ID is rejected
- expired approval is rejected
- denied approval is rejected
- unauthorized Telegram user cannot approve
- provider delivery failure does not approve
- approval store failure fails closed

Integration tests:

- fake approval provider approves one request
- fake approval provider denies one request
- fake Telegram callback with authorized user approves
- fake Telegram callback with unauthorized user is audited and rejected

Manual verification:

- run goclaw with local stdio interceptor
- request read-only command
- request mutating command
- approve through Telegram
- confirm exact command executes once
- retry approval ID and confirm rejection
- deny a command and confirm it never executes

## Implementation Phases

### Phase 1: Core Approval Engine

- Add approval mode configuration.
- Add approval request struct and fingerprinting.
- Add local approval store.
- Add fake provider for tests.
- Wire `execute_remote` and `transfer_file` to remote approval mode.

### Phase 2: Providers

- Add Telegram provider.
- Add local CLI fallback commands.
- Add provider configuration and docs.

### Phase 3: Goclaw Packaging

- Document local stdio integration.
- Document reuse of Luna instructions and skills as policy material.
- Add service account and SSH agent setup guidance.

## Resolved Decisions

1. goclaw and the interceptor communicate through local-only stdio.
2. Approval is command-by-command.
3. Phase 1 supports a single configured human approver.
4. The provider abstraction remains open; Telegram is the first provider.
5. The local CLI is a fallback provider.
6. The design is for human-plus-agent operations, not CI/CD.
7. `allow_mutations=true` remains for legacy local mode but is not trusted in remote approval mode.

