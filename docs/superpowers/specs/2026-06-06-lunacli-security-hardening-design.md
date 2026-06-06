# Lunacli Security Hardening Design

**Status:** Approved  
**Date:** 2026-06-06

## Goal

Fix the verified remote-signing, approval, logging, host-key, and command
classification vulnerabilities while reducing false mutation prompts.

## Architecture

### Canonical SSH Target

Resolve the caller's SSH alias once into a canonical target containing the
effective user, resolved host, resolved IP, port, and known-host identity. Use
that target consistently for policy classification, command approval,
proxy-signing requests, connection cache keys, known-host verification, and
dialing. The original alias remains display-only.

### Direct Local-Key Binding

For proxy `local-key` mode, capture the destination host public key accepted by
the SSH `HostKeyCallback`. Before the hosted signer requests a signature, attach
that key as `sdk.SignatureRequest.DestinationHostPublicKey`. The proxy validates
the user-auth sign data against this client-reported destination key and
disables lease reuse for direct clients.

### Approval Binding

Approval records keep a redacted command for display, but verification uses a
process-random keyed HMAC over the exact host, command, and timeout. Consuming
an approval is an atomic `approved` to `consumed` transition.

### Command Classification

Parsed executable semantics establish a risk floor that policy cannot
downgrade. Executable-specific checks identify mutating flags and forbidden
wrappers. Raw-string forbidden checks remain only for shell syntax attacks that
cannot safely be represented as executable-aware checks.

Harmless literal text and redirects to `/dev/null`, standard streams, or file
descriptor duplication do not raise risk.

### Host Keys and Logging

Known-host checks respect `HostKeyAlias`. `accept-new` is rejected because the
current client does not persist accepted keys. All command logs use redacted
commands, and authorization headers are redacted before approval delivery.

## Testing

Every fix receives a regression test first. Focused package tests run after
each change, followed by `make test`, `go vet ./...`, and structured
`autoreview`.

