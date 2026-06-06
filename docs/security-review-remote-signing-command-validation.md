# Security Review: Remote Signing and Command Validation

**Reviewed:** 2026-06-06  
**Scope:** Remote proxy signing, SSH target binding, command classification,
command approval binding, and mutation false positives.

## Executive Summary

The review found several concrete security-boundary failures:

- Bundled read-only policy rules allow some mutating commands without approval.
- SSH aliases and DNS resolution can cause the approved target to differ from
  the host actually dialed.
- Concurrent callers can consume one approved command more than once.
- Raw commands and authorization headers can leak credentials.
- Approval fingerprints are bound to redacted commands rather than the exact
  command.
- Execution wrappers can bypass permanently forbidden command detection.

The classifier also produces avoidable approval prompts and permanent blocks
when dangerous-looking text is only a literal argument or output is redirected
without writing a persistent file.

## Implementation Status

Implemented on 2026-06-06:

- Proxy local-key signatures now bind the destination host key accepted by the
  SSH host-key callback using the updated SDK's
  `DestinationHostPublicKey` field.
- Approval and execution bind to one canonical user/IP/port while preserving
  the original SSH alias for policy, identity-file, and `HostKeyAlias` checks.
- Approval verification uses an exact-command keyed HMAC and atomic
  approved-to-consumed transition.
- Command logs and approval displays redact authorization headers and curl
  credentials while preserving visible command suffixes.
- Parsed semantic checks prevent broad allow rules from downgrading known
  mutations, and harmless literal/output-only cases avoid false prompts.
- `HostKeyAlias` is respected and non-persistent `accept-new` is rejected.

Residual upstream limitation:

- The current `luna-ztrust` SDK `CertRequest` and `SignatureRequest` contain no
  target-port field. Lunacli binds approval, cache lookup, and dialing to the
  canonical port locally, but proxy-side port policy requires a future
  SDK/proxy contract extension.

## Findings

### P1: Bundled Read-Only Rules Can Mutate State

The bundled policy allows unrestricted or overly broad command forms:

- `date -s @0`
- `hostname compromised`
- `ss -K ...`
- `ip link set eth0 down`
- `ip route add default via 10.0.0.1`
- `journalctl --vacuum-time=1s`

These commands can currently match an `allow` rule and execute without command
approval.

References:

- `internal/onboard/bundle_src/policy.yml:22`
- `internal/engine/engine.go:174`

Recommended fix:

- Define explicit read-only command profiles and reject known mutating flags.
- Do not allow a policy rule to downgrade a semantic mutation to read-only.

### P1: Approved Proxy Target Can Differ From Dialed Target

Proxy signing resolves the caller-provided host, while the connection pool
separately applies SSH `HostName` and performs its own DNS resolution. Command
policy and approval fingerprints also use the caller-supplied alias.

An alias can therefore display and authorize one target while dialing another.
The proxy request also does not bind the SSH port.

References:

- `internal/ssh/auth_proxy.go:117`
- `internal/ssh/pool.go:252`

Recommended fix:

- Resolve one canonical target before policy checks, command approval, proxy
  signing, known-host verification, cache lookup, and dialing.
- Bind proxy approval to user, canonical host/IP, port, and host key.

### P1: Approved Command Can Be Consumed Concurrently More Than Once

`VerifyAndConsume` reads an approved record and later calls `MarkConsumed`.
`MemoryStore.MarkConsumed` unconditionally changes the status. Two concurrent
retries can both observe `approved`, both consume successfully, and both execute
the command.

References:

- `internal/approval/service.go:186`
- `internal/approval/store_memory.go:72`

Recommended fix:

- Replace `MarkConsumed` with an atomic compare-and-swap operation that only
  transitions `approved` to `consumed`.

### P1: Commands and Authorization Headers Can Leak Credentials

`execute_remote` logs raw commands repeatedly. Secret redaction also explicitly
does not redact header-shaped arguments, allowing commands such as:

```sh
curl -H 'Authorization: Bearer secret' https://example.test
```

to expose credentials in logs and approval messages.

References:

- `internal/tools/execute_remote.go:68`
- `internal/approval/redact.go:73`

Recommended fix:

- Log only redacted commands or request fingerprints.
- Parse shell arguments and redact `Authorization` and
  `Proxy-Authorization` header values, URL userinfo, and authentication flags.

### P1: Approvals Are Not Bound to the Exact Command

Approval fingerprints are computed from the redacted command. Commands that
differ only in a redacted secret produce the same fingerprint and can reuse the
same approval ID.

Reference:

- `internal/approval/request.go:31`

Recommended fix:

- Store and display only the redacted command.
- Separately bind verification using a server-keyed HMAC over the exact original
  request.

### P1: Execution Wrappers Can Bypass Permanently Forbidden Detection

Forbidden privilege commands are primarily recognized at the command start or
after shell separators. Wrappers can convert a forbidden command into a
mutating command that becomes executable after approval:

```sh
command sudo id
nohup sudo id
timeout 10 sudo id
```

Wrapper handling currently covers only basic `env` and `xargs` cases.

References:

- `internal/engine/hardcoded.go:38`
- `internal/engine/hardcoded.go:110`

Recommended fix:

- Recursively unwrap known execution wrappers.
- Treat unknown or dynamic execution wrappers as mutating or forbidden.
- Add parsed-command tests for all permanently forbidden operations.

### P2: Host-Key Verification Ignores HostKeyAlias

Known-host verification always checks the resolved dial address and ignores SSH
`HostKeyAlias`. With `StrictHostKeyChecking=accept-new`, a configured key under
`HostKeyAlias` can appear absent and a different key can be accepted.

Additionally, accepted keys are not persisted, so each process restart can
accept another new key.

Reference:

- `internal/ssh/pool.go:474`

Recommended fix:

- Respect `HostKeyAlias` when selecting the known-host identity.
- Persist keys accepted through `accept-new`, or reject that mode for this
  zero-trust execution path.

### Resolved: Local-Key Signing Requires Session Binding

The updated SDK accepts the destination host public key for direct
`x/crypto/ssh` clients. Lunacli captures the accepted host key and supplies it
on every local-key signature request.

References:

- `internal/ssh/auth_proxy.go:250`
- `go.mod:31`

Status: implemented.

## Reducing False Mutation Prompts

Redirects to `/dev/null` are already treated as read-only. The remaining false
positives primarily come from scanning full command strings instead of
evaluating parsed executable semantics.

Examples that should not require approval:

```sh
echo 'rm -rf /'
grep 'mkfs' /var/log/audit.log
grep 'curl --data x' logfile
uptime 2>&1
journalctl >/dev/stdout
```

Recommended classifier design:

1. Parse the shell command and compute semantic risk for every executable.
2. Allow policy rules to raise risk, but never downgrade semantic mutations.
3. Scope mutating-flag checks to the actual executable.
4. Add pure-output profiles for `echo`, `printf`, `pwd`, `true`, and `false`.
5. Recognize file-descriptor duplication, closure, and standard stream targets
   as non-persistent redirects.
6. Add command-aware validators for `ip`, `date`, `hostname`, `ss`,
   `journalctl`, `sort`, `uniq`, and `diff`.
7. Inspect nested execution only for constructs that actually execute commands,
   such as substitutions and execution wrappers.

## Review Record

Structured review commands:

```sh
autoreview --mode local --thinking high
```

Verification:

- `make test`: passed all packages.
- Focused approval, engine, tools, and SSH tests: passed.
- `go vet ./...`: no issues.
- `git diff --check`: no issues.

Accepted structured-review findings were fixed across five passes, including
canonical/alias policy matching, exact-target execution, timeout wrappers,
attached options, persistent-writing command forms, quoted credential
redaction, and preservation of visible command suffixes.

Rejected or residual reviewer output:

- Returning only the first hosted signer is a reliability issue, not a security
  boundary failure.
- Proxy-side SSH port authorization cannot be implemented until the
  `luna-ztrust` SDK/proxy request contract adds a target-port field.
- The final structured-review rerun was attempted but the Codex reviewer hit
  its usage limit before returning a result.
