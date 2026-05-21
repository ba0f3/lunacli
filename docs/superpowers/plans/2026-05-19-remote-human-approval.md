# Remote Human Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add remote human approval for mutating `execute_remote` calls when Luna runs in goclaw-style untrusted mode, with pluggable approval providers, durable audit storage, and legacy OpenCode `allow_mutations` preserved in local mode.

**Architecture:** New `interceptor/internal/approval` package owns mode config, secret redaction, request fingerprinting, SQLite persistence, provider dispatch, and consume-once verification. `execute_remote` delegates mutating decisions to an `approval.Gate` before SSH execution. Phase 1 ships a fake provider and full policy tests; Phase 2 adds Telegram and local CLI; Phase 3 documents goclaw stdio integration and SSH key isolation.

**Tech Stack:** Go 1.25.5, `github.com/mark3labs/mcp-go`, existing `internal/security` classifier, `modernc.org/sqlite` (pure Go, no CGO), stdlib `crypto/sha256`, `encoding/json`, `os/exec` for CLI principal checks.

**Spec:** [`docs/superpowers/specs/2026-05-16-remote-human-approval-design.md`](../specs/2026-05-16-remote-human-approval-design.md)

**Codebase note:** `transfer_file` was removed from the interceptor (`AGENTS.md`). This plan wires **only `execute_remote`**. Re-introducing SFTP upload as a mutating tool is a follow-up after this plan.

---

## File Structure

**Phase 1 — core engine**

- Create `interceptor/internal/approval/mode.go` — `LUNA_APPROVAL_MODE`, TTL, store path env parsing.
- Create `interceptor/internal/approval/redact.go` — deterministic secret redaction for commands and env-like tokens.
- Create `interceptor/internal/approval/redact_test.go` — redaction unit tests.
- Create `interceptor/internal/approval/request.go` — `ExecuteRemoteRequest`, status enum, canonical JSON types.
- Create `interceptor/internal/approval/fingerprint.go` — `ComputeFingerprint(canonicalRedactedBody)`.
- Create `interceptor/internal/approval/fingerprint_test.go` — stability and secret-non-leakage tests.
- Create `interceptor/internal/approval/store.go` — `Store` interface + audit event types.
- Create `interceptor/internal/approval/store_sqlite.go` — SQLite implementation, `0600` file creation.
- Create `interceptor/internal/approval/store_sqlite_test.go` — store CRUD and fail-closed tests.
- Create `interceptor/internal/approval/service.go` — create pending, approve/deny, verify+consume, expire sweep.
- Create `interceptor/internal/approval/service_test.go` — state machine unit tests.
- Create `interceptor/internal/approval/provider.go` — `Provider` interface + multi-provider fan-out.
- Create `interceptor/internal/approval/fake_provider.go` — test/double provider with programmatic approve/deny.
- Create `interceptor/internal/approval/gate.go` — maps classifier + mode → execute / block / permission required.
- Create `interceptor/internal/approval/gate_test.go` — remote vs local mode matrix tests.
- Create `interceptor/internal/approval/permission_text.go` — formats `PERMISSION_REQUIRED` with `approval_id`, `expires_at`, `fingerprint_prefix`.
- Modify `interceptor/internal/tools/execute_remote.go` — `approval_id` param, `Gate` integration.
- Modify `interceptor/internal/tools/tools.go` — pass `*approval.Gate` into `registerExecuteRemote`.
- Modify `interceptor/main.go` — construct approval service + gate from env.
- Modify `interceptor/go.mod` — add `modernc.org/sqlite`.

**Phase 2 — providers**

- Create `interceptor/internal/approval/provider_telegram.go` — Telegram Bot API send + callback verify.
- Create `interceptor/internal/approval/provider_telegram_test.go` — httptest for send/callback paths.
- Create `interceptor/internal/approval/provider_localcli.go` — hooks used by CLI (no network).
- Create `interceptor/internal/approval/cli.go` — `approvals list|show|approve|deny` handlers.
- Modify `interceptor/main.go` — dispatch `approvals` subcommand when `os.Args[1] == "approvals"`.
- Create `docs/remote-approval.md` — operator configuration for Telegram + CLI.

**Phase 3 — goclaw packaging**

- Create `docs/goclaw-integration.md` — stdio MCP wiring, policy reuse, trust boundaries.
- Modify `README.md`, `AGENTS.md` — approval modes and `approval_id` workflow.
- Modify `instructions/agents/deployer.md` — remote mode uses `approval_id`, not `allow_mutations`.

---

## Phase 1: Core Approval Engine

### Task 1: Approval mode configuration

**Files:**
- Create: `interceptor/internal/approval/mode.go`
- Create: `interceptor/internal/approval/mode_test.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/mode_test.go`:

```go
package approval

import (
	"testing"
	"time"
)

func TestLoadConfigFromEnv_LocalDefault(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_MODE", "")
	t.Setenv("LUNA_APPROVAL_STORE", "")
	t.Setenv("LUNA_APPROVAL_TTL", "")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.Mode != ModeLocal {
		t.Fatalf("Mode = %q, want local", cfg.Mode)
	}
}

func TestLoadConfigFromEnv_RemoteRequiresStore(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_MODE", "remote")
	t.Setenv("LUNA_APPROVAL_STORE", "")
	t.Setenv("LUNA_APPROVAL_TTL", "5m")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error when remote mode has empty store path")
	}
}

func TestLoadConfigFromEnv_RemoteParsesTTL(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_MODE", "remote")
	t.Setenv("LUNA_APPROVAL_STORE", t.TempDir()+"/approvals.db")
	t.Setenv("LUNA_APPROVAL_TTL", "2m")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.Mode != ModeRemote {
		t.Fatalf("Mode = %q, want remote", cfg.Mode)
	}
	if cfg.TTL != 2*time.Minute {
		t.Fatalf("TTL = %s, want 2m", cfg.TTL)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestLoadConfigFromEnv -v
```

Expected: FAIL — package `approval` does not exist or `LoadConfigFromEnv` undefined.

- [ ] **Step 3: Implement mode configuration**

Create `interceptor/internal/approval/mode.go`:

```go
package approval

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Mode string

const (
	ModeLocal  Mode = "local"
	ModeRemote Mode = "remote"
)

type Config struct {
	Mode  Mode
	Store string
	TTL   time.Duration
}

func LoadConfigFromEnv() (Config, error) {
	rawMode := strings.ToLower(strings.TrimSpace(os.Getenv("LUNA_APPROVAL_MODE")))
	cfg := Config{
		Mode: ModeLocal,
		TTL:  5 * time.Minute,
	}
	switch rawMode {
	case "", "local":
		cfg.Mode = ModeLocal
	case "remote":
		cfg.Mode = ModeRemote
	default:
		return Config{}, fmt.Errorf("invalid LUNA_APPROVAL_MODE %q", rawMode)
	}

	cfg.Store = strings.TrimSpace(os.Getenv("LUNA_APPROVAL_STORE"))
	if ttlRaw := strings.TrimSpace(os.Getenv("LUNA_APPROVAL_TTL")); ttlRaw != "" {
		d, err := time.ParseDuration(ttlRaw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid LUNA_APPROVAL_TTL: %w", err)
		}
		cfg.TTL = d
	}

	if cfg.Mode == ModeRemote && cfg.Store == "" {
		return Config{}, fmt.Errorf("LUNA_APPROVAL_STORE is required when LUNA_APPROVAL_MODE=remote")
	}
	return cfg, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestLoadConfigFromEnv -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/approval/mode.go interceptor/internal/approval/mode_test.go
git commit -m "feat(approval): add approval mode configuration from env"
```

---

### Task 2: Secret redaction package

**Files:**
- Create: `interceptor/internal/approval/redact.go`
- Create: `interceptor/internal/approval/redact_test.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/redact_test.go`:

```go
package approval

import "testing"

func TestRedactSecrets_CommandFlags(t *testing.T) {
	in := "curl --password supersecret --token=abc123 -H Authorization: Bearer xyz"
	got := RedactSecrets(in)
	want := "curl --password [REDACTED] --token=[REDACTED] -H Authorization: Bearer xyz"
	if got != want {
		t.Fatalf("RedactSecrets() = %q, want %q", got, want)
	}
}

func TestRedactSecrets_EnvAssignment(t *testing.T) {
	in := "export AWS_SECRET_ACCESS_KEY=secret"
	got := RedactSecrets(in)
	want := "export AWS_SECRET_ACCESS_KEY=[REDACTED]"
	if got != want {
		t.Fatalf("RedactSecrets() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestRedactSecrets -v
```

Expected: FAIL — `RedactSecrets` undefined.

- [ ] **Step 3: Implement redaction**

Create `interceptor/internal/approval/redact.go` (port flag-name logic from `inventory_parse.go`, add `KEY=value` env redaction for names containing `secret`, `password`, `token`, `key`):

```go
package approval

import (
	"regexp"
	"strings"
)

const RedactionVersion = "luna.redact.v1"

var secretArgNames = []string{
	"password", "passwd", "pwd", "secret", "token", "apikey", "api-key",
	"access-key", "access_key", "private-key", "private_key", "credential",
	"credentials", "auth", "authorization",
}

var envAssignPattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

func RedactSecrets(input string) string {
	out := redactSecretLikeArgs(input)
	fields := strings.Fields(out)
	for i, field := range fields {
		if m := envAssignPattern.FindStringSubmatch(field); m != nil {
			if isSecretName(m[1]) {
				fields[i] = m[1] + "=[REDACTED]"
			}
		}
	}
	return strings.Join(fields, " ")
}

func redactSecretLikeArgs(command string) string {
	fields := strings.Fields(command)
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		key := strings.TrimLeft(field, "-")
		if idx := strings.Index(key, "="); idx >= 0 {
			name := key[:idx]
			if isSecretName(name) {
				prefix := field[:strings.Index(field, "=")+1]
				fields[i] = prefix + "[REDACTED]"
			}
			continue
		}
		if isSecretName(key) && i+1 < len(fields) {
			fields[i+1] = "[REDACTED]"
		}
	}
	return strings.Join(fields, " ")
}

func isSecretName(name string) bool {
	normalized := strings.ToLower(strings.Trim(name, " -_"))
	for _, candidate := range secretArgNames {
		if normalized == candidate || strings.Contains(normalized, candidate) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestRedactSecrets -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/approval/redact.go interceptor/internal/approval/redact_test.go
git commit -m "feat(approval): add deterministic secret redaction"
```

---

### Task 3: Request model and fingerprint

**Files:**
- Create: `interceptor/internal/approval/request.go`
- Create: `interceptor/internal/approval/fingerprint.go`
- Create: `interceptor/internal/approval/fingerprint_test.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/fingerprint_test.go`:

```go
package approval

import "testing"

func TestComputeFingerprint_StableForSameRedactedRequest(t *testing.T) {
	req := ExecuteRemoteRequest{
		Tool:       "execute_remote",
		Host:       "web1",
		Command:    "systemctl restart nginx",
		TimeoutSec: 30,
	}
	body, err := CanonicalJSON(req)
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	a := ComputeFingerprint(body)
	b := ComputeFingerprint(body)
	if a != b || len(a) != 64 {
		t.Fatalf("fingerprints differ or wrong length: %q %q", a, b)
	}
}

func TestComputeFingerprint_ChangesWhenCommandChanges(t *testing.T) {
	bodyA, _ := CanonicalJSON(ExecuteRemoteRequest{Tool: "execute_remote", Host: "web1", Command: "systemctl restart nginx"})
	bodyB, _ := CanonicalJSON(ExecuteRemoteRequest{Tool: "execute_remote", Host: "web1", Command: "systemctl restart apache2"})
	if ComputeFingerprint(bodyA) == ComputeFingerprint(bodyB) {
		t.Fatal("expected different fingerprints for different commands")
	}
}

func TestFingerprintPrefix(t *testing.T) {
	if got := FingerprintPrefix("abcdef0123456789"); got != "abcdef01" {
		t.Fatalf("FingerprintPrefix() = %q, want abcdef01", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run 'TestComputeFingerprint|TestFingerprintPrefix' -v
```

Expected: FAIL

- [ ] **Step 3: Implement request + fingerprint**

Create `interceptor/internal/approval/request.go`:

```go
package approval

import "encoding/json"

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
	StatusConsumed Status = "consumed"
)

type ExecuteRemoteRequest struct {
	Tool       string  `json:"tool"`
	Host       string  `json:"host"`
	Command    string  `json:"command"`
	TimeoutSec float64 `json:"timeout_sec,omitempty"`
}

func CanonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func BuildExecuteRemoteRequest(host, command string, timeoutSec float64) (ExecuteRemoteRequest, []byte, string, error) {
	redacted := RedactSecrets(command)
	req := ExecuteRemoteRequest{
		Tool:       "execute_remote",
		Host:       host,
		Command:    redacted,
		TimeoutSec: timeoutSec,
	}
	body, err := CanonicalJSON(req)
	if err != nil {
		return ExecuteRemoteRequest{}, nil, "", err
	}
	return req, body, ComputeFingerprint(body), nil
}
```

Create `interceptor/internal/approval/fingerprint.go`:

```go
package approval

import (
	"crypto/sha256"
	"encoding/hex"
)

func ComputeFingerprint(canonicalBody []byte) string {
	sum := sha256.Sum256(canonicalBody)
	return hex.EncodeToString(sum[:])
}

func FingerprintPrefix(fingerprint string) string {
	if len(fingerprint) < 8 {
		return fingerprint
	}
	return fingerprint[:8]
}
```

Add to `request.go` a helper used by tests for sorted-key stability if needed later; for this struct, `json.Marshal` field order is fixed by struct definition.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run 'TestComputeFingerprint|TestFingerprintPrefix' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/approval/request.go interceptor/internal/approval/fingerprint.go interceptor/internal/approval/fingerprint_test.go
git commit -m "feat(approval): add execute_remote request fingerprinting"
```

---

### Task 4: SQLite approval store

**Files:**
- Modify: `interceptor/go.mod`
- Create: `interceptor/internal/approval/store.go`
- Create: `interceptor/internal/approval/store_sqlite.go`
- Create: `interceptor/internal/approval/store_sqlite_test.go`

- [ ] **Step 1: Add sqlite dependency**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go get modernc.org/sqlite
```

Expected: `go.mod` updated with `modernc.org/sqlite`.

- [ ] **Step 2: Write the failing test**

Create `interceptor/internal/approval/store.go`:

```go
package approval

import "time"

type Record struct {
	ID                string
	Tool              string
	Host              string
	RedactedCommand   string
	NormalizedBody    []byte
	Classification    string
	Reason            string
	Fingerprint       string
	Status            Status
	CreatedAt         time.Time
	ExpiresAt         time.Time
	DecidedAt         *time.Time
	Approver          string
	RedactionVersion  string
}

type AuditEvent struct {
	ApprovalID string
	EventType  string
	Detail     string
	CreatedAt  time.Time
}

type Store interface {
	InsertPending(r Record) error
	Get(id string) (Record, error)
	UpdateStatus(id string, status Status, approver string, decidedAt time.Time) error
	MarkConsumed(id string, at time.Time) error
	AppendAudit(e AuditEvent) error
	Close() error
}
```

Create `interceptor/internal/approval/store_sqlite_test.go`:

```go
package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStore_InsertAndGetPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	rec := Record{
		ID:               "apr-test-1",
		Tool:             "execute_remote",
		Host:             "web1",
		RedactedCommand:  "systemctl restart nginx",
		NormalizedBody:   []byte(`{"tool":"execute_remote","host":"web1","command":"systemctl restart nginx"}`),
		Classification:   "mutating",
		Reason:           "mutating command",
		Fingerprint:      "abc",
		Status:           StatusPending,
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		RedactionVersion: RedactionVersion,
	}
	if err := store.InsertPending(rec); err != nil {
		t.Fatalf("InsertPending() error = %v", err)
	}
	got, err := store.Get("apr-test-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("Status = %q, want pending", got.Status)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestSQLiteStore -v
```

Expected: FAIL — `OpenSQLiteStore` undefined.

- [ ] **Step 4: Implement SQLite store**

Create `interceptor/internal/approval/store_sqlite.go` with:

- `OpenSQLiteStore(path string) (Store, error)` — `os.MkdirAll` parent `0700`, open DB, run migrations, `chmod 0600` on DB file when newly created.
- Schema tables `approvals` and `audit_events` matching fields in `Record` / `AuditEvent`.
- `InsertPending`, `Get`, `UpdateStatus`, `MarkConsumed`, `AppendAudit`, `Close`.
- `Get` returns `fmt.Errorf("approval not found")` for missing IDs.

- [ ] **Step 5: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestSQLiteStore -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/go.mod interceptor/go.sum interceptor/internal/approval/store.go interceptor/internal/approval/store_sqlite.go interceptor/internal/approval/store_sqlite_test.go
git commit -m "feat(approval): add SQLite approval store"
```

---

### Task 5: Approval service (state machine)

**Files:**
- Create: `interceptor/internal/approval/service.go`
- Create: `interceptor/internal/approval/service_test.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/service_test.go`:

```go
package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func TestService_ApproveThenConsumeOnce(t *testing.T) {
	store, _ := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	svc := NewService(store, Config{Mode: ModeRemote, TTL: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	req, body, fp, err := BuildExecuteRemoteRequest("web1", "systemctl restart nginx", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	pending, err := svc.CreatePending("execute_remote", req, body, fp, "mutating", "restart")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := svc.Approve(pending.ID, "human@local", "fake"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := svc.VerifyAndConsume(pending.ID, req, body, fp); err != nil {
		t.Fatalf("first VerifyAndConsume() error = %v", err)
	}
	if err := svc.VerifyAndConsume(pending.ID, req, body, fp); err == nil {
		t.Fatal("expected error reusing consumed approval")
	}
}

func TestService_RejectMismatchedCommand(t *testing.T) {
	store, _ := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	svc := NewService(store, Config{Mode: ModeRemote, TTL: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	reqA, bodyA, fpA, _ := BuildExecuteRemoteRequest("web1", "systemctl restart nginx", 30)
	pending, _ := svc.CreatePending("execute_remote", reqA, bodyA, fpA, "mutating", "restart")
	_ = svc.Approve(pending.ID, "human@local", "fake")

	reqB, bodyB, fpB, _ := BuildExecuteRemoteRequest("web1", "systemctl restart apache2", 30)
	if fpA == fpB {
		t.Fatal("test setup: fingerprints should differ")
	}
	if err := svc.VerifyAndConsume(pending.ID, reqB, bodyB, fpB); err == nil {
		t.Fatal("expected mismatch rejection")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestService -v
```

Expected: FAIL

- [ ] **Step 3: Implement service**

Create `interceptor/internal/approval/service.go` with:

- `type Service struct { store Store; cfg Config; now func() time.Time }`
- `NewService(store Store, cfg Config) *Service` — default `now = time.Now`.
- `CreatePending(tool string, req ExecuteRemoteRequest, body []byte, fingerprint, class, reason string) (PendingInfo, error)` — generates ID with `uuid` from `github.com/google/uuid` (already indirect dep), inserts pending record, appends audit `request_created`.
- `type PendingInfo struct { ID, Fingerprint, FingerprintPrefix string; ExpiresAt time.Time }`
- `Approve(id, approver, provider string) error` — only from `pending`, audit `approved`.
- `Deny(id, approver, provider string) error` — audit `denied`.
- `VerifyAndConsume(id string, req ExecuteRemoteRequest, body []byte, fingerprint string) error` — checks status approved, not expired, fingerprint match, then `MarkConsumed` + audit `consumed`.
- `ExpireDue()` — mark pending past `ExpiresAt` as `expired` (call from CreatePending or gate).

Return typed errors: `ErrNotFound`, `ErrConsumed`, `ErrExpired`, `ErrDenied`, `ErrMismatch`, `ErrStoreUnavailable`.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestService -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/approval/service.go interceptor/internal/approval/service_test.go
git commit -m "feat(approval): add approval service state machine"
```

---

### Task 6: Fake approval provider

**Files:**
- Create: `interceptor/internal/approval/provider.go`
- Create: `interceptor/internal/approval/fake_provider.go`
- Create: `interceptor/internal/approval/fake_provider_test.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/fake_provider_test.go`:

```go
package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFakeProvider_ApproveViaCallback(t *testing.T) {
	store, _ := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	svc := NewService(store, Config{Mode: ModeRemote, TTL: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	provider := NewFakeProvider(svc, "fake")
	req, body, fp, _ := BuildExecuteRemoteRequest("web1", "touch /tmp/luna-approval-test", 30)
	pending, _ := svc.CreatePending("execute_remote", req, body, fp, "mutating", "touch")
	if err := provider.Notify(pending, req); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	provider.Approve(pending.ID, "test-human")
	if err := svc.VerifyAndConsume(pending.ID, req, body, fp); err != nil {
		t.Fatalf("VerifyAndConsume() error = %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestFakeProvider -v
```

Expected: FAIL

- [ ] **Step 3: Implement provider interface + fake**

Create `interceptor/internal/approval/provider.go`:

```go
package approval

type Provider interface {
	Name() string
	Notify(p PendingInfo, req ExecuteRemoteRequest) error
}

type ProviderSet struct {
	providers []Provider
}

func NewProviderSet(providers ...Provider) *ProviderSet {
	return &ProviderSet{providers: providers}
}

func (p *ProviderSet) NotifyAll(pending PendingInfo, req ExecuteRemoteRequest) error {
	var firstErr error
	for _, provider := range p.providers {
		if err := provider.Notify(pending, req); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
```

Create `interceptor/internal/approval/fake_provider.go`:

```go
package approval

type FakeProvider struct {
	svc      *Service
	name     string
	approver string
}

func NewFakeProvider(svc *Service, name string) *FakeProvider {
	return &FakeProvider{svc: svc, name: name, approver: "test-human"}
}

func (f *FakeProvider) Name() string { return f.name }

func (f *FakeProvider) Notify(PendingInfo, ExecuteRemoteRequest) error { return nil }

func (f *FakeProvider) Approve(id string, approver string) error {
	if approver == "" {
		approver = f.approver
	}
	return f.svc.Approve(id, approver, f.name)
}

func (f *FakeProvider) Deny(id string, approver string) error {
	if approver == "" {
		approver = f.approver
	}
	return f.svc.Deny(id, approver, f.name)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestFakeProvider -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/approval/provider.go interceptor/internal/approval/fake_provider.go interceptor/internal/approval/fake_provider_test.go
git commit -m "feat(approval): add fake approval provider for tests"
```

---

### Task 7: Permission gate (local vs remote)

**Files:**
- Create: `interceptor/internal/approval/gate.go`
- Create: `interceptor/internal/approval/permission_text.go`
- Create: `interceptor/internal/approval/gate_test.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/gate_test.go`:

```go
package approval

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/security"
)

func TestGate_LocalModeUsesAllowMutations(t *testing.T) {
	gate := NewGate(Config{Mode: ModeLocal}, nil, nil)
	res := gate.CheckExecuteRemote(security.CheckResult{Class: security.Mutating}, "h", "touch /tmp/x", 30, false, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("Kind = %v, want permission required without allow_mutations", res.Kind)
	}
	res = gate.CheckExecuteRemote(security.CheckResult{Class: security.Mutating}, "h", "touch /tmp/x", 30, true, "")
	if res.Kind != GateExecute {
		t.Fatalf("Kind = %v, want execute when allow_mutations=true", res.Kind)
	}
}

func TestGate_RemoteModeRejectsAllowMutationsAlone(t *testing.T) {
	store, _ := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	svc := NewService(store, Config{Mode: ModeRemote, TTL: time.Minute})
	providers := NewProviderSet(NewFakeProvider(svc, "fake"))
	gate := NewGate(Config{Mode: ModeRemote}, svc, providers)

	res := gate.CheckExecuteRemote(security.CheckResult{Class: security.Mutating, Reason: "mutating"}, "h", "touch /tmp/x", 30, true, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("Kind = %v, want permission required", res.Kind)
	}
	if res.ApprovalID == "" {
		t.Fatal("expected approval id in remote pending response")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestGate -v
```

Expected: FAIL

- [ ] **Step 3: Implement gate**

Create `interceptor/internal/approval/gate.go`:

```go
package approval

import "github.com/ba0f3/lunacli/internal/security"

type GateKind int

const (
	GateExecute GateKind = iota
	GateBlocked
	GatePermissionRequired
)

type GateResult struct {
	Kind              GateKind
	BlockedText       string
	PermissionText    string
	ApprovalID        string
	ExpiresAt         time.Time
	FingerprintPrefix string
}

type Gate struct {
	cfg       Config
	svc       *Service
	providers *ProviderSet
}

func NewGate(cfg Config, svc *Service, providers *ProviderSet) *Gate {
	return &Gate{cfg: cfg, svc: svc, providers: providers}
}

func (g *Gate) CheckExecuteRemote(check security.CheckResult, host, command string, timeoutSec float64, allowMutations bool, approvalID string) GateResult {
	if check.Class == security.Forbidden {
		return GateResult{Kind: GateBlocked}
	}
	if check.Class == security.ReadOnly {
		return GateResult{Kind: GateExecute}
	}

	if g.cfg.Mode == ModeLocal {
		if allowMutations {
			return GateResult{Kind: GateExecute}
		}
		return GateResult{Kind: GatePermissionRequired}
	}

	if g.svc == nil {
		return GateResult{Kind: GatePermissionRequired}
	}

	req, body, fp, err := BuildExecuteRemoteRequest(host, command, timeoutSec)
	if err != nil {
		return GateResult{Kind: GatePermissionRequired}
	}

	if approvalID != "" {
		if err := g.svc.VerifyAndConsume(approvalID, req, body, fp); err != nil {
			return GateResult{Kind: GatePermissionRequired}
		}
		return GateResult{Kind: GateExecute}
	}

	if allowMutations {
		return GateResult{Kind: GatePermissionRequired}
	}

	pending, err := g.svc.CreatePending("execute_remote", req, body, fp, check.Class.String(), check.Reason)
	if err != nil {
		return GateResult{Kind: GatePermissionRequired}
	}
	_ = g.providers.NotifyAll(pending, req)
	return GateResult{
		Kind:              GatePermissionRequired,
		PermissionText:    FormatPermissionRequired(check.Reason, command, pending),
		ApprovalID:        pending.ID,
		ExpiresAt:         pending.ExpiresAt,
		FingerprintPrefix: pending.FingerprintPrefix,
	}
}
```

Create `interceptor/internal/approval/permission_text.go`:

```go
package approval

import "fmt"

func FormatPermissionRequired(reason, command string, p PendingInfo) string {
	return fmt.Sprintf(
		"PERMISSION_REQUIRED: %s\n\nCommand: %q\n\napproval_id: %s\nexpires_at: %s\nfingerprint_prefix: %s\n\nApprove out of band, then retry with the same host and command plus approval_id.",
		reason, command, p.ID, p.ExpiresAt.UTC().Format(time.RFC3339), p.FingerprintPrefix,
	)
}
```

Add `import "time"` to `permission_text.go`.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestGate -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/approval/gate.go interceptor/internal/approval/gate_test.go interceptor/internal/approval/permission_text.go
git commit -m "feat(approval): add local and remote permission gate"
```

---

### Task 8: Wire `execute_remote` and main

**Files:**
- Modify: `interceptor/internal/tools/execute_remote.go`
- Modify: `interceptor/internal/tools/tools.go`
- Modify: `interceptor/main.go`

- [ ] **Step 1: Write the failing integration test**

Create `interceptor/internal/tools/execute_remote_approval_test.go`:

```go
package tools

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestExecuteRemote_RemoteModeCreatesPendingApproval(t *testing.T) {
	store, err := approval.OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := approval.NewService(store, approval.Config{Mode: approval.ModeRemote, TTL: time.Minute})
	fake := approval.NewFakeProvider(svc, "fake")
	gate := approval.NewGate(approval.Config{Mode: approval.ModeRemote}, svc, approval.NewProviderSet(fake))

	// Use gate directly: full MCP test needs SSH pool mock; gate test covers policy.
	req, body, fp, _ := approval.BuildExecuteRemoteRequest("example.com", "touch /tmp/luna-test", 30)
	res := gate.CheckExecuteRemote(securityMutating(), "example.com", "touch /tmp/luna-test", 30, false, "")
	if res.ApprovalID == "" {
		t.Fatal("expected approval id")
	}
	fake.Approve(res.ApprovalID, "human")
	if err := svc.VerifyAndConsume(res.ApprovalID, req, body, fp); err != nil {
		t.Fatalf("VerifyAndConsume() error = %v", err)
	}
}

func securityMutating() security.CheckResult {
	return security.CheckResult{Class: security.Mutating, Reason: "mutating"}
}
```

Add import for security in test file:

```go
"github.com/ba0f3/lunacli/internal/security"
```

Fix helper:

```go
func securityMutating() security.CheckResult {
	return security.CheckResult{Class: security.Mutating, Reason: "mutating"}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/tools -run TestExecuteRemote_RemoteMode -v
```

Expected: FAIL until `execute_remote` uses gate (test may pass after Task 7 if only gate tested — adjust message: FAIL if helper wrong).

- [ ] **Step 3: Wire gate into execute_remote**

In `registerExecuteRemote`, add parameter `gate *approval.Gate`. Add MCP optional string `approval_id`.

Replace mutating branch with:

```go
gateRes := gate.CheckExecuteRemote(check, host, command, timeoutSec, allowMutations, req.GetString("approval_id", ""))
switch gateRes.Kind {
case approval.GateBlocked:
	// existing BLOCKED text
case approval.GatePermissionRequired:
	text := gateRes.PermissionText
	if text == "" {
		text = fmt.Sprintf("PERMISSION_REQUIRED: %s\n\nCommand: %q\n\nAsk the human user for explicit approval, then retry with allow_mutations=true.", check.Reason, command)
	}
	return mcp.NewToolResultText(text), nil
case approval.GateExecute:
	// fall through to pool.Execute
}
```

Update `tools.Register` signature:

```go
func Register(s *server.MCPServer, pool *ssh.Pool, gate *approval.Gate) {
```

In `main.go`:

```go
cfg, err := approval.LoadConfigFromEnv()
if err != nil { log.Fatalf("approval config: %v", err) }

var gate *approval.Gate
if cfg.Mode == approval.ModeRemote {
	store, err := approval.OpenSQLiteStore(cfg.Store)
	if err != nil { log.Fatalf("approval store: %v", err) }
	svc := approval.NewService(store, cfg)
	providers := approval.NewProviderSet(approval.NewFakeProvider(svc, "fake"))
	gate = approval.NewGate(cfg, svc, providers)
} else {
	gate = approval.NewGate(cfg, nil, nil)
}
tools.Register(s, pool, gate)
```

- [ ] **Step 4: Run full interceptor tests**

Run:

```bash
cd /home/tui/repos/luna/interceptor && make test
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /home/tui/repos/luna
git add interceptor/internal/tools/execute_remote.go interceptor/internal/tools/tools.go interceptor/internal/tools/execute_remote_approval_test.go interceptor/main.go
git commit -m "feat(approval): wire remote approval gate into execute_remote"
```

---

## Phase 2: Telegram and local CLI providers

### Task 9: Local CLI `approvals` subcommand with principal check

**Files:**
- Create: `interceptor/internal/approval/cli.go`
- Create: `interceptor/internal/approval/cli_auth.go`
- Create: `interceptor/internal/approval/cli_test.go`
- Modify: `interceptor/main.go`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/cli_auth_test.go`:

```go
package approval

import "testing"

func TestAuthorizeCLIApprover_AllowsConfiguredUser(t *testing.T) {
	t.Setenv("LUNA_CLI_APPROVER_USERS", "1000")
	if err := AuthorizeCLIApprover("1000"); err != nil {
		t.Fatalf("AuthorizeCLIApprover() error = %v", err)
	}
}

func TestAuthorizeCLIApprover_RejectsUnknownUser(t *testing.T) {
	t.Setenv("LUNA_CLI_APPROVER_USERS", "1000")
	if err := AuthorizeCLIApprover("9999"); err == nil {
		t.Fatal("expected unauthorized error")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestAuthorizeCLIApprover -v
```

Expected: FAIL

- [ ] **Step 3: Implement CLI auth + handlers**

`cli_auth.go` — read `LUNA_CLI_APPROVER_USERS` (comma-separated UIDs), compare `os.Getuid()` string.

`cli.go` — `RunApprovalsCLI(args []string, svc *Service) error` implementing `list`, `show <id>`, `approve <id>`, `deny <id>`; approve/deny call `AuthorizeCLIApprover` first and append audit `approved` / `denied` / `unauthorized_cli_attempt` on failure.

`main.go` — at top of `main()`:

```go
if len(os.Args) > 1 && os.Args[1] == "approvals" {
	runApprovalsCLI(os.Args[2:])
	return
}
```

- [ ] **Step 4: Run tests**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run 'TestAuthorizeCLIApprover|TestRunApprovalsCLI' -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add interceptor/internal/approval/cli.go interceptor/internal/approval/cli_auth.go interceptor/internal/approval/cli_auth_test.go interceptor/main.go
git commit -m "feat(approval): add local CLI approvals subcommand"
```

---

### Task 10: Telegram provider

**Files:**
- Create: `interceptor/internal/approval/provider_telegram.go`
- Create: `interceptor/internal/approval/provider_telegram_test.go`
- Modify: `interceptor/main.go` — register Telegram when `LUNA_APPROVAL_PROVIDER` contains `telegram`
- Create: `docs/remote-approval.md`

- [ ] **Step 1: Write the failing test**

Create `interceptor/internal/approval/provider_telegram_test.go` using `httptest.Server` to assert `sendMessage` POST includes `approval_id` button `callback_data` format `approve:<id>` / `deny:<id>` (opaque ID only, not full command).

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestTelegram -v
```

Expected: FAIL

- [ ] **Step 3: Implement Telegram provider**

`provider_telegram.go`:

- Config from `LUNA_TELEGRAM_BOT_TOKEN` or `LUNA_TELEGRAM_BOT_TOKEN_FILE`, `LUNA_TELEGRAM_APPROVER_USER_ID`, optional `LUNA_TELEGRAM_CHAT_ID`.
- `Notify` sends message with inline keyboard Approve/Deny.
- `HandleCallback(userID, data string) error` — verify user ID, parse action, call `svc.Approve` / `svc.Deny`, audit unauthorized callbacks.

Document webhook/long-polling choice in `docs/remote-approval.md` (phase 2: recommend separate small `luna-telegram-webhook` process or manual `getUpdates` loop — pick **long-polling helper command** `luna-interceptor telegram poll` to avoid inbound HTTP on interceptor).

- [ ] **Step 4: Run tests**

Run:

```bash
cd /home/tui/repos/luna/interceptor && go test ./internal/approval -run TestTelegram -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add interceptor/internal/approval/provider_telegram.go interceptor/internal/approval/provider_telegram_test.go docs/remote-approval.md interceptor/main.go
git commit -m "feat(approval): add Telegram approval provider"
```

---

## Phase 3: Goclaw packaging and docs

### Task 11: Goclaw integration and operator docs

**Files:**
- Create: `docs/goclaw-integration.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `instructions/agents/deployer.md`

- [ ] **Step 1: Write goclaw integration doc**

Create `docs/goclaw-integration.md` covering:

- goclaw and interceptor on same host, stdio MCP only.
- `LUNA_APPROVAL_MODE=remote` for goclaw; never trust `allow_mutations`.
- Retry flow with `approval_id`.
- Reuse Luna `instructions/` and skills as policy material only.
- SSH: interceptor user owns `SSH_AUTH_SOCK`; goclaw separate Unix user; no agent forwarding.

- [ ] **Step 2: Update project docs**

`README.md` — add approval modes table and link to `docs/remote-approval.md`.

`AGENTS.md` — document `PERMISSION_REQUIRED` fields (`approval_id`, `expires_at`, `fingerprint_prefix`) and remote vs local mode.

`deployer.md` — add remote-mode example:

```text
execute_remote host=<h> command="systemctl restart <svc>" approval_id="<id-from-permission-required>"
```

- [ ] **Step 3: Verify docs references**

Run:

```bash
cd /home/tui/repos/luna && rg -n 'transfer_file|allow_mutations=true' README.md AGENTS.md instructions/agents/deployer.md docs/goclaw-integration.md
```

Expected: deployer still documents `allow_mutations` for **local mode** only; remote examples use `approval_id`.

- [ ] **Step 4: Commit**

```bash
git add docs/goclaw-integration.md docs/remote-approval.md README.md AGENTS.md instructions/agents/deployer.md
git commit -m "docs: add goclaw remote approval integration guide"
```

---

## Spec coverage self-review

| Spec requirement | Task |
|------------------|------|
| Remote vs local approval modes | Task 1, 7, 8 |
| `allow_mutations` not authority in remote mode | Task 7, 8 |
| Command-by-command fingerprint | Task 3, 5 |
| Mandatory redaction before persistence | Task 2, 5 |
| SQLite store `0600`, fail closed | Task 4 |
| Fake provider for tests | Task 6 |
| `execute_remote` + `approval_id` | Task 8 |
| `transfer_file` | **Deferred** — tool removed; note in plan header |
| Telegram provider | Task 10 |
| Local CLI fallback | Task 9 |
| Audit events | Task 4, 5, 9, 10 |
| goclaw stdio + SSH guidance | Task 11 |
| Optional `list_pending_approvals` MCP tool | **Deferred** (YAGNI phase 1) |

## Placeholder scan

No `TBD`, `TODO`, or "similar to task" steps in this plan.

---

## Execution handoff

**Plan complete and saved to `docs/superpowers/plans/2026-05-19-remote-human-approval.md`.**

**Before implementing:** use **superpowers:using-git-worktrees** to create an isolated branch (do not implement on `main` without explicit consent).

**Two execution options:**

1. **Subagent-driven (recommended)** — fresh subagent per task, review between tasks.
2. **Inline execution** — **superpowers:executing-plans** in this session with checkpoints after Phase 1.

**Which approach do you want?**
