# Lunacli Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden proxy signing, approvals, host-key verification, command validation, and secret handling.

**Architecture:** Resolve one canonical SSH target and share it across authorization and dialing. Bind direct local-key signing to the accepted destination host key, bind approvals to exact requests with keyed HMAC and atomic consumption, and establish an executable-aware semantic risk floor before policy evaluation.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh`, `mvdan.cc/sh/v3/syntax`, local `luna-ztrust/sdk`.

---

### Task 1: Direct local-key destination binding and canonical SSH targets

**Files:**
- Modify: `internal/ssh/target.go`
- Modify: `internal/ssh/ssh_config_host.go`
- Modify: `internal/ssh/auth_proxy.go`
- Modify: `internal/ssh/pool.go`
- Test: `internal/ssh/auth_proxy_test.go`
- Test: `internal/ssh/known_hosts_test.go`
- Test: `internal/ssh/pool_test.go`

- [x] Write failing tests proving aliases resolve before signing/dialing and the accepted host key reaches `DestinationHostPublicKey`.
- [x] Run `go test ./internal/ssh` and confirm the tests fail.
- [x] Implement canonical target resolution and host-key capture for hosted signers.
- [x] Respect `HostKeyAlias` and reject unsupported non-persistent `accept-new`.
- [x] Run `go test ./internal/ssh`.

### Task 2: Exact and single-use approvals

**Files:**
- Modify: `internal/approval/request.go`
- Modify: `internal/approval/service.go`
- Modify: `internal/approval/store.go`
- Modify: `internal/approval/store_memory.go`
- Test: `internal/approval/fingerprint_test.go`
- Test: `internal/approval/service_test.go`
- Test: `internal/approval/store_memory_test.go`

- [x] Write failing tests proving secret-only command changes mismatch and concurrent consumption succeeds once.
- [x] Run `go test ./internal/approval` and confirm the tests fail.
- [x] Add keyed exact-request binding and atomic approved-to-consumed storage transition.
- [x] Run `go test ./internal/approval`.

### Task 3: Secret-safe command logging and approval display

**Files:**
- Modify: `internal/approval/redact.go`
- Modify: `internal/tools/execute_remote.go`
- Test: `internal/approval/redact_test.go`

- [x] Write failing tests for authorization headers and authentication flags.
- [x] Run `go test ./internal/approval` and confirm the tests fail.
- [x] Implement redaction and replace raw command logs with redacted commands.
- [x] Run `go test ./internal/approval ./internal/tools`.

### Task 4: Semantic command risk floor and false-positive reduction

**Files:**
- Modify: `internal/engine/engine.go`
- Modify: `internal/engine/hardcoded.go`
- Modify: `internal/onboard/bundle_src/policy.yml`
- Test: `internal/engine/engine_test.go`

- [x] Write failing regression tests for bundled-policy mutations, forbidden wrappers, literal text, and harmless redirects.
- [x] Run `go test ./internal/engine` and confirm the tests fail.
- [x] Implement executable-aware risk checks and redirect handling.
- [x] Enforce a semantic risk floor beneath bundled read-only rules.
- [x] Run `go test ./internal/engine ./internal/onboard`.

### Task 5: Integration verification and review

**Files:**
- Modify: `docs/security-review-remote-signing-command-validation.md`

- [x] Update the review document with remediation status and residual risks.
- [x] Run `gofmt` on changed Go files.
- [x] Run `make test`.
- [x] Run `go vet ./...`.
- [x] Run structured `autoreview` and resolve accepted findings.
