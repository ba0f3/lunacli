# MCP-only in-memory approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simplify Luna to a single `luna serve` stdio MCP entrypoint with Telegram-only OOB approval state held in process memory (no SQLite, no `exec`/`approvals`/`telegram` subcommands).

**Architecture:** `cmd/serve.go` constructs `approval.NewMemoryStore()`, `Service`, and a required `TelegramProvider`. A background goroutine runs `TelegramProvider.Poll(ctx)` for the server lifetime. `execute_remote` uses the existing `Gate` unchanged. Plain `luna` prints help (already landed in `cmd/root.go`).

**Tech Stack:** Go 1.25+, `github.com/mark3labs/mcp-go`, existing `internal/approval`, `internal/engine`, `internal/ssh`, `internal/tools`.

**Spec:** [docs/superpowers/specs/2026-05-22-luna-mcp-inmemory-approval.md](../specs/2026-05-22-luna-mcp-inmemory-approval-design.md)

---

## File map

| File | Responsibility |
|------|----------------|
| `internal/approval/store_memory.go` | In-memory `Store` implementation |
| `internal/approval/store_memory_test.go` | Unit tests for memory store |
| `internal/approval/serve_bootstrap.go` | `BootstrapServeApproval(settings) (gate, tg, cancel, err)` — memory + telegram + poll ctx |
| `cmd/serve.go` | Use bootstrap; remove SQLite open |
| `cmd/exec.go` | **Delete** |
| `cmd/approvals.go` | **Delete** |
| `cmd/telegram.go` | **Delete** |
| `internal/approval/cli.go` | **Delete** (no CLI approvals) |
| `internal/approval/cli_auth.go` | **Delete** |
| `internal/approval/cli_auth_test.go` | **Delete** |
| `internal/approval/wait.go` | **Delete** (only used by exec) |
| `internal/approval/wait_test.go` | **Delete** |
| `internal/approval/telegram_sync.go` | **Delete** (CLI-only message sync) |
| `internal/approval/telegram_sync_test.go` | **Delete** |
| `internal/approval/providers_env.go` | Add `RequireTelegramProvider` for serve |
| `docs/oob-approval.md` | MCP-only, in-memory, explicit `luna serve` |
| `docs/zero-trust-interceptor.md` | Command table trim |
| `examples/luna.d/README.md` | Remove exec/approvals instructions |
| `.config/luna.config.json` (example) | Drop `approval.store`, set `provider: telegram` |

Keep unchanged: `store_sqlite.go` + tests (package tests), `gate.go`, `execute_remote.go`, `telegram_poll.go`, `telegram_message.go`.

---

### Task 1: In-memory approval store

**Files:**
- Create: `internal/approval/store_memory.go`
- Create: `internal/approval/store_memory_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/approval/store_memory_test.go
package approval

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryStore_PendingApproveConsume(t *testing.T) {
	st := NewMemoryStore()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	rec := Record{
		ID: "id-1", Tool: executeRemoteToolName, Host: "h", RedactedCommand: "touch /tmp/x",
		NormalizedBody: []byte(`{}`), Classification: "mutating", Reason: "r",
		Fingerprint: "fp", Status: StatusPending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), RedactionVersion: RedactionVersion,
	}
	if err := st.InsertPending(rec); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateStatus("id-1", StatusApproved, "human", now); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("id-1")
	if err != nil || got.Status != StatusApproved {
		t.Fatalf("Get() = %+v, %v", got, err)
	}
	if err := st.MarkConsumed("id-1", now); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get("id-1")
	if err != nil || got.Status != StatusConsumed {
		t.Fatalf("after consume: %+v, %v", got, err)
	}
}

func TestMemoryStore_ExpireDue(t *testing.T) {
	st := NewMemoryStore()
	past := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	rec := Record{
		ID: "exp-1", Tool: executeRemoteToolName, Host: "h", RedactedCommand: "x",
		NormalizedBody: []byte(`{}`), Classification: "mutating", Reason: "r",
		Fingerprint: "fp", Status: StatusPending,
		CreatedAt: past, ExpiresAt: past.Add(time.Second), RedactionVersion: RedactionVersion,
	}
	if err := st.InsertPending(rec); err != nil {
		t.Fatal(err)
	}
	now := past.Add(2 * time.Second)
	if err := st.ExpireDue(now); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("exp-1")
	if err != nil || got.Status != StatusExpired {
		t.Fatalf("status = %q, err = %v", got.Status, err)
	}
}

func TestMemoryStore_SetTelegramMessage(t *testing.T) {
	st := NewMemoryStore()
	now := time.Now().UTC()
	rec := Record{
		ID: "tg-1", Tool: executeRemoteToolName, Host: "h", RedactedCommand: "x",
		NormalizedBody: []byte(`{}`), Classification: "mutating", Reason: "r",
		Fingerprint: "fp", Status: StatusPending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), RedactionVersion: RedactionVersion,
	}
	if err := st.InsertPending(rec); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTelegramMessage("tg-1", 222, 99); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("tg-1")
	if err != nil || got.TelegramChatID != 222 || got.TelegramMessageID != 99 {
		t.Fatalf("telegram ids = %d/%d", got.TelegramChatID, got.TelegramMessageID)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	st := NewMemoryStore()
	_, err := st.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/approval -run TestMemoryStore -v`  
Expected: FAIL — `NewMemoryStore` undefined

- [ ] **Step 3: Implement `MemoryStore`**

```go
// internal/approval/store_memory.go
package approval

import (
	"sync"
	"time"
)

type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (m *MemoryStore) InsertPending(r Record) error {
	if r.Status != StatusPending {
		return errPendingStatusRequired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.records[r.ID]; exists {
		return ErrMismatch
	}
	m.records[r.ID] = r
	return nil
}

func (m *MemoryStore) Get(id string) (Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}

func (m *MemoryStore) ListPending() ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Record
	for _, r := range m.records {
		if r.Status == StatusPending {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MemoryStore) UpdateStatus(id string, status Status, approver string, decidedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = status
	r.Approver = approver
	t := decidedAt.UTC()
	r.DecidedAt = &t
	m.records[id] = r
	return nil
}

func (m *MemoryStore) MarkConsumed(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = StatusConsumed
	m.records[id] = r
	return nil
}

func (m *MemoryStore) AppendAudit(_ AuditEvent) error { return nil }

func (m *MemoryStore) ExpireDue(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now = now.UTC()
	for id, r := range m.records {
		if r.Status == StatusPending && now.After(r.ExpiresAt) {
			r.Status = StatusExpired
			t := now
			r.DecidedAt = &t
			m.records[id] = r
		}
	}
	return nil
}

func (m *MemoryStore) SetTelegramMessage(id string, chatID, messageID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.TelegramChatID = chatID
	r.TelegramMessageID = messageID
	m.records[id] = r
	return nil
}

func (m *MemoryStore) Close() error { return nil }

var errPendingStatusRequired = errors.New("InsertPending requires status pending")
```

Add `"errors"` import at top of `store_memory.go` (fix package — use `fmt.Errorf` or `errors.New`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/approval -run TestMemoryStore -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/approval/store_memory.go internal/approval/store_memory_test.go
git commit -m "feat(approval): add in-memory store for MCP-only mode"
```

---

### Task 2: Serve bootstrap (memory + required Telegram)

**Files:**
- Create: `internal/approval/serve_bootstrap.go`
- Create: `internal/approval/serve_bootstrap_test.go`
- Modify: `internal/approval/providers_env.go`

- [ ] **Step 1: Add `RequireTelegramProvider`**

```go
// internal/approval/providers_env.go — add:
func RequireTelegramProvider(s *config.Settings, svc *Service) (*TelegramProvider, error) {
	tg, err := NewTelegramProviderFromSettings(svc, s)
	if err != nil {
		return nil, fmt.Errorf("telegram required for luna serve: %w", err)
	}
	return tg, nil
}
```

- [ ] **Step 2: Write bootstrap test (httptest telegram, memory store)**

```go
// internal/approval/serve_bootstrap_test.go — TestBootstrapServeApproval_RequiresTelegram
// Skip if no token in env; use httptest Server + TelegramProviderOptions APIBaseURL
// Assert gate non-nil, cancel func stops poll without hang (use context.WithTimeout)
```

Minimal test: call `BootstrapServeApproval` with settings missing telegram → error contains `telegram required`.

- [ ] **Step 3: Implement bootstrap**

```go
// internal/approval/serve_bootstrap.go
package approval

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

type ServeApproval struct {
	Gate   *Gate
	PollCancel context.CancelFunc
}

func BootstrapServeApproval(settings *config.Settings) (*ServeApproval, error) {
	appCfg, err := LoadConfig(settings)
	if err != nil {
		return nil, err
	}
	store := NewMemoryStore()
	svc := NewService(store, appCfg)
	tg, err := RequireTelegramProvider(settings, svc)
	if err != nil {
		return nil, err
	}
	providers := NewProviderSet(tg)
	gate := NewGate(appCfg, svc, providers)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := tg.Poll(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("telegram poll: %v", err)
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = svc.ExpireDue()
			}
		}
	}()

	return &ServeApproval{Gate: gate, PollCancel: cancel}, nil
}
```

Fix `ExpireDue` call: `svc.ExpireDue()` needs `now` — use `svc.ExpireDue(time.Now())` or add package method on Service (already exists: `func (s *Service) ExpireDue() error` — check service.go).

Read service for ExpireDue wrapper.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/approval -run Bootstrap -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/approval/serve_bootstrap.go internal/approval/serve_bootstrap_test.go internal/approval/providers_env.go
git commit -m "feat(approval): bootstrap serve with memory store and telegram poll"
```

---

### Task 3: Wire `cmd/serve.go`

**Files:**
- Modify: `cmd/serve.go`

- [ ] **Step 1: Replace SQLite bootstrap with `BootstrapServeApproval`**

```go
// cmd/serve.go Run — replace lines opening SQLite with:
boot, err := approval.BootstrapServeApproval(settings)
if err != nil {
	log.Fatalf("approval: %v", err)
}
defer boot.PollCancel()
gate := boot.Gate
```

Remove: `OpenSQLiteStore`, `RemoteProvidersFromSettings`, manual `NewGate` construction.

- [ ] **Step 2: Build and smoke**

Run: `go build -o ./bin/luna .`  
Expected: success

Run: `./bin/luna 2>&1 | head -3`  
Expected: usage text (not serve)

- [ ] **Step 3: Commit**

```bash
git add cmd/serve.go
git commit -m "feat(serve): use in-memory approvals and embedded telegram poll"
```

---

### Task 4: Remove CLI commands and dead code

**Files:**
- Delete: `cmd/exec.go`, `cmd/approvals.go`, `cmd/telegram.go`
- Delete: `internal/approval/cli.go`, `cli_auth.go`, `cli_auth_test.go`
- Delete: `internal/approval/wait.go`, `wait_test.go`
- Delete: `internal/approval/telegram_sync.go`, `telegram_sync_test.go`

- [ ] **Step 1: Delete files listed above**

- [ ] **Step 2: Verify build and full test suite**

Run: `go build -o ./bin/luna .`  
Run: `go test ./...`  
Expected: all pass (fix any broken imports — none should reference deleted cmds)

- [ ] **Step 3: Commit**

```bash
git add -A cmd/ internal/approval/
git commit -m "refactor(cli): remove exec, approvals, telegram subcommands and CLI-only approval code"
```

---

### Task 5: Gate integration test with memory store

**Files:**
- Create: `internal/approval/gate_memory_test.go`

- [ ] **Step 1: Write test**

```go
func TestGate_MemoryStore_MutatingFlow(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Minute})
	fake := NewFakeProvider(svc, "fake")
	gate := NewGate(Config{}, svc, NewProviderSet(fake))
	// First call: permission required + approval id
	// Approve via svc.Approve
	// Second call with approval_id: GateExecute
}
```

Use existing pattern from `gate_test.go` + `execute_remote_approval_test.go`.

- [ ] **Step 2: Run and commit**

Run: `go test ./internal/approval -run Gate_Memory -v`  
Expected: PASS

```bash
git add internal/approval/gate_memory_test.go
git commit -m "test(approval): gate flow with memory store"
```

---

### Task 6: Documentation and example config

**Files:**
- Modify: `docs/oob-approval.md`
- Modify: `docs/zero-trust-interceptor.md`
- Modify: `examples/luna.d/README.md`
- Modify: `examples/luna.config.json` (if present in repo root examples)

- [ ] **Step 1: Update docs**

Key points to document:
- Only `luna serve` (explicit subcommand)
- Approvals live in MCP process memory; restart clears pending
- Telegram required; configure `telegram.*` and `approval.ttl`
- MCP client must use `["/path/to/luna", "serve"]`
- No `approvals.db`, no CLI approve

- [ ] **Step 2: Commit**

```bash
git add docs/ examples/
git commit -m "docs: MCP-only in-memory approval and explicit luna serve"
```

---

### Task 7: Final verification

- [ ] **Step 1: Full test and lint**

Run: `go test ./...`  
Run: `go build -o ./bin/luna .`  
Expected: pass / success

- [ ] **Step 2: Manual checklist (operator)**

1. `luna` → help only  
2. `luna serve` with valid `policy.yml` + telegram config → stderr log `starting zero-trust` + poll running  
3. Mutating `execute_remote` from MCP client → Telegram message  
4. Tap Approve → retry with `approval_id` → SSH runs  
5. Restart `luna serve` → previous pending IDs invalid (expected)

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| MCP-only `luna serve` | Task 3, 4 |
| No exec/approvals/telegram CLI | Task 4 |
| In-memory store | Task 1 |
| Telegram poll in serve | Task 2, 3 |
| No approvals.db | Task 3 (no SQLite open) |
| Telegram-only approve | Task 2 `RequireTelegramProvider` |
| TTL expiry | Task 1 `ExpireDue`, Task 2 ticker |
| `execute_remote` contract unchanged | Task 5 (gate test) |
| Plain `luna` → usage | Already in `cmd/root.go` |
| Document single-process assumption | Task 6 |
| Keep sqlite for package tests only | No task removes `store_sqlite.go` |

## Out of scope (do not implement)

- SQLite flock / offset files from superseded spec
- CLI TTY gates
- `luna exec` wait loop
- Persist approvals to disk

---

## Self-review notes

- `store_memory.go` snippet uses `errors` — import included in implementation step.
- `svc.ExpireDue()` — verify `Service` exposes `ExpireDue() error` calling `store.ExpireDue(s.now())`; adjust bootstrap ticker if method signature differs.
- Placeholder scan: no TBD tasks remaining.
