# Luna SDK proxy signing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Default lunacli remote SSH to **proxy-signed credentials** via in-process `luna-sdk`, while **lunacli still dials targets directly**; keep command approval (Telegram in `luna.config.json`) unchanged.

**Architecture:** Add `AuthProvider` (`SignersFor(target)`). `proxy` mode calls luna-sdk → luna-proxy for access approval + signing; `Pool.getClient` uses returned signers only (no `SSH_AUTH_SOCK` / disk key fallback). Dial path (`gossh.Dial`, `known_hosts`, host-key algorithms) stays in `pool.go`.

**Tech Stack:** Go 1.25+, `github.com/ba0f3/luna-ztrust/luna-sdk`, existing `internal/approval`, `internal/engine`, `golang.org/x/crypto/ssh`.

**Spec:** [docs/superpowers/specs/2026-06-01-luna-sdk-proxy-transport-design.md](../specs/2026-06-01-luna-sdk-proxy-transport-design.md)

**Prerequisite:** Clone `luna-sdk` at `../ba0f3/luna-ztrust/luna-sdk` (relative to lunacli root). Confirm exported API for `SignersFor(user, host, port)` (names may differ — adapt `auth_proxy.go` once).

---

## File map

| File | Action | Responsibility |
|------|--------|----------------|
| `go.mod` / `go.sum` | Modify | `require` + `replace` luna-sdk |
| `internal/config/settings.go` | Modify | `TransportSettings`, merge, env accessors |
| `internal/config/settings_test.go` | Create/Modify | Transport defaults + env |
| `internal/ssh/target.go` | Create | `Target` + `TargetFromString` |
| `internal/ssh/auth.go` | Create | `AuthProvider`, `NewAuthProvider`, mode warnings |
| `internal/ssh/auth_direct.go` | Create | `directAuth` — moved `collectAuthSigners` |
| `internal/ssh/auth_proxy.go` | Create | SDK wrapper for proxy signing |
| `internal/ssh/auth_agent.go` | Create | SDK luna-agent (opt-in) |
| `internal/ssh/access_errors.go` | Create | `ACCESS_*` sentinel errors + MCP text helpers |
| `internal/ssh/auth_test.go` | Create | Fakes + mode selection tests |
| `internal/ssh/pool.go` | Modify | `Pool.auth`, `NewPool(cfg)`, `getClient` uses `SignersFor` |
| `internal/ssh/pool_test.go` | Create | Assert proxy mode skips agent signers (fake auth) |
| `internal/audit/transport.go` | Create (optional) | Or log from `auth.go`: `transport_mode`, `transport_non_recommended` |
| `cmd/serve.go` | Modify | `ssh.NewPool(settings)` |
| `cmd/ssh-debug/main.go` | Modify | Load settings, print transport mode, use `NewPool` |
| `README.md` | Modify | Two-layer approval + direct dial diagram |
| `docs/goclaw-integration.md` | Modify | Signing vs relay clarification |
| `internal/ssh/AGENTS.md` | Modify | AuthProvider table |
| `AGENTS.md` | Modify | One-line transport note |

Keep unchanged: `internal/approval/*`, `internal/tools/execute_remote.go` (except if mapping `ACCESS_*` in tool layer — prefer errors bubble from `pool.Execute`).

---

### Task 0: Wire `luna-sdk` module

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/ssh/auth_proxy.go` (minimal compile against SDK)

- [ ] **Step 1: Add module dependency**

In `go.mod`:

```go
require github.com/ba0f3/luna-ztrust/luna-sdk v0.0.0

replace github.com/ba0f3/luna-ztrust/luna-sdk => ../ba0f3/luna-ztrust/luna-sdk
```

Run: `go mod tidy`  
Expected: succeeds only when `luna-sdk` path exists.

- [ ] **Step 2: Document SDK surface in a comment block**

At top of `auth_proxy.go`, record actual types after reading SDK:

```go
// Proxy signing (no SSH relay):
//   client := sdk.NewProxyClient(endpoint)
//   signers, err := client.SignersFor(ctx, sdk.Target{User, Host, Port})
// Map sdk.ErrAccessDenied → access_errors.go
```

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum internal/ssh/auth_proxy.go
git commit -m "chore: add luna-sdk module dependency for proxy signing"
```

---

### Task 1: Transport config

**Files:**
- Modify: `internal/config/settings.go`
- Create: `internal/config/settings_transport_test.go`

- [ ] **Step 1: Write failing tests**

```go
// internal/config/settings_transport_test.go
package config

import "testing"

func TestTransportMode_DefaultProxy(t *testing.T) {
	s := &Settings{file: FileSettings{}}
	if got := s.TransportMode(); got != "proxy" {
		t.Fatalf("TransportMode() = %q, want proxy", got)
	}
}

func TestTransportMode_EnvOverride(t *testing.T) {
	t.Setenv("LUNA_TRANSPORT_MODE", "direct")
	s := &Settings{file: FileSettings{Transport: TransportSettings{Mode: "proxy"}}}
	if got := s.TransportMode(); got != "direct" {
		t.Fatalf("TransportMode() = %q, want direct", got)
	}
}

func TestProxyEndpoint_RequiredFields(t *testing.T) {
	s := &Settings{file: FileSettings{Transport: TransportSettings{Mode: "proxy"}}}
	if ep := s.ProxyEndpoint(); ep != "" {
		t.Fatalf("ProxyEndpoint() = %q, want empty", ep)
	}
	t.Setenv("LUNA_PROXY_ENDPOINT", "https://proxy.test")
	if ep := s.ProxyEndpoint(); ep != "https://proxy.test" {
		t.Fatalf("ProxyEndpoint() = %q", ep)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run Transport -v`  
Expected: FAIL (`TransportMode` undefined)

- [ ] **Step 3: Implement schema**

Add to `FileSettings`:

```go
type TransportSettings struct {
	Mode  string              `json:"mode"`
	Proxy ProxyTransportSettings `json:"proxy"`
}
type ProxyTransportSettings struct {
	Endpoint string `json:"endpoint"`
}
```

Add methods:

```go
func (s *Settings) TransportMode() string {
	m := envFirst("LUNA_TRANSPORT_MODE", s.file.Transport.Mode)
	if m == "" {
		return "proxy"
	}
	return m
}

func (s *Settings) ProxyEndpoint() string {
	return envFirst("LUNA_PROXY_ENDPOINT", s.file.Transport.Proxy.Endpoint)
}
```

Extend `mergeFileSettings` for `Transport` (same pattern as `Telegram`).

Add `ValidateTransport() error` — if mode is `proxy` and endpoint empty, return error.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -run Transport -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/settings.go internal/config/settings_transport_test.go
git commit -m "feat(config): add transport mode and proxy endpoint settings"
```

---

### Task 2: `AuthProvider` + direct mode

**Files:**
- Create: `internal/ssh/target.go`, `internal/ssh/auth.go`, `internal/ssh/auth_direct.go`, `internal/ssh/auth_test.go`
- Modify: `internal/ssh/pool.go` — move `collectAuthSigners` + helpers to `auth_direct.go` (re-export or same package)

- [ ] **Step 1: Write failing test**

```go
// internal/ssh/auth_test.go
func TestNewAuthProvider_DirectUsesDiskAndAgent(t *testing.T) {
	// use Settings with mode direct; assert provider type *directAuth
}

func TestDirectAuth_SignersFor_CallsCollectAuthSigners(t *testing.T) {
	// table test with host "example.com" — can use t.TempDir for empty home
}
```

- [ ] **Step 2: Implement `target.go`**

```go
type Target struct {
	User, Host, Port string
	Raw              string
}

func TargetFromString(raw string) Target {
	u, h, p := parseTarget(raw)
	return Target{User: u, Host: h, Port: p, Raw: raw}
}
```

- [ ] **Step 3: Implement `auth.go` + `auth_direct.go`**

```go
type AuthProvider interface {
	SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error)
}

func NewAuthProvider(cfg *config.Settings) (AuthProvider, error) {
	switch cfg.TransportMode() {
	case "proxy":
		if cfg.ProxyEndpoint() == "" {
			return nil, fmt.Errorf("transport.mode proxy requires transport.proxy.endpoint or LUNA_PROXY_ENDPOINT")
		}
		return newProxyAuth(cfg)
	case "luna-agent":
		log.Printf("[SSH] WARNING: transport.mode=luna-agent is not recommended (weak target binding)")
		return newAgentAuth(cfg)
	case "direct":
		log.Printf("[SSH] WARNING: transport.mode=direct is not recommended (no proxy access approval)")
		return &directAuth{}, nil
	default:
		return nil, fmt.Errorf("unknown transport.mode %q", cfg.TransportMode())
	}
}
```

Move `collectAuthSigners`, `expandIdentityFilePath`, `sharedAgentSigners` usage into `directAuth.SignersFor` only.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/ssh/ -run Auth -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ssh/target.go internal/ssh/auth.go internal/ssh/auth_direct.go internal/ssh/auth_test.go internal/ssh/pool.go
git commit -m "feat(ssh): add AuthProvider with direct mode"
```

---

### Task 3: Access error types

**Files:**
- Create: `internal/ssh/access_errors.go`, extend `internal/ssh/access_errors_test.go`

- [ ] **Step 1: Write tests**

```go
func TestFormatAccessError_Denied(t *testing.T) {
	err := ErrAccessDenied
	got := FormatAccessError(Target{Raw: "u@h:22"}, err)
	if !strings.HasPrefix(got, "ACCESS_DENIED:") {
		t.Fatalf("got %q", got)
	}
}
```

Define:

```go
var (
	ErrAccessRequired = errors.New("access required")
	ErrAccessDenied   = errors.New("access denied")
	ErrAccessExpired  = errors.New("access expired")
)

func FormatAccessError(t Target, err error) string { /* map to ACCESS_*: prefixes */ }
```

- [ ] **Step 2: Run + commit**

```bash
go test ./internal/ssh/ -run Access -v
git add internal/ssh/access_errors.go internal/ssh/access_errors_test.go
git commit -m "feat(ssh): add ACCESS_* error helpers for proxy signing"
```

---

### Task 4: Proxy `AuthProvider` (SDK)

**Files:**
- Modify: `internal/ssh/auth_proxy.go`

- [ ] **Step 1: Implement `proxyAuth.SignersFor`**

```go
type proxyAuth struct {
	client *sdk.ProxyClient // use real SDK type name
}

func (p *proxyAuth) SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error) {
	signers, err := p.client.SignersFor(ctx, sdk.Target{User: t.User, Host: t.Host, Port: t.Port})
	if err != nil {
		return nil, mapSDKAccessError(err, t)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("%s", FormatAccessError(t, ErrAccessDenied))
	}
	return signers, nil
}
```

Implement `mapSDKAccessError` by inspecting SDK typed errors or string codes documented in Task 0.

- [ ] **Step 2: Unit test with fake SDK interface**

Define narrow interface in `auth_proxy.go`:

```go
type proxySignerClient interface {
	SignersFor(ctx context.Context, user, host, port string) ([]gossh.Signer, error)
}
```

Test `proxyAuth` with fake returning `ErrAccessDenied` from SDK.

- [ ] **Step 3: Integration test tag (optional)**

```go
//go:build integration

func TestProxyAuth_Live(t *testing.T) { /* requires LUNA_PROXY_ENDPOINT */ }
```

- [ ] **Step 4: Commit**

```bash
git add internal/ssh/auth_proxy.go internal/ssh/auth_proxy_test.go
git commit -m "feat(ssh): proxy AuthProvider via luna-sdk signing"
```

---

### Task 5: Pool uses `AuthProvider` (direct dial unchanged)

**Files:**
- Modify: `internal/ssh/pool.go`
- Create: `internal/ssh/pool_test.go`

- [ ] **Step 1: Write failing test**

```go
type recordingAuth struct {
	calls []Target
	signers []gossh.Signer
}

func (r *recordingAuth) SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error) {
	r.calls = append(r.calls, t)
	return r.signers, nil
}

func TestGetClient_UsesAuthProviderSigners(t *testing.T) {
	// Skip if no signers: use generated test key
	// Not testing real dial — test via unexported getClient is hard; instead:
	// Export test hook or test collect path:
	// Refactor: p.signersFor(target) called from getClient — test that function
}
```

Prefer extracting:

```go
func (p *Pool) signersFor(ctx context.Context, target string) ([]gossh.Signer, error) {
	t := TargetFromString(target)
	return p.auth.SignersFor(ctx, t)
}
```

Test `signersFor` calls recording auth.

- [ ] **Step 2: Change `Pool` struct**

```go
type Pool struct {
	mu      sync.Mutex
	clients map[string]*gossh.Client
	auth    AuthProvider
}

func NewPool(cfg *config.Settings) (*Pool, error) {
	auth, err := NewAuthProvider(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.TransportMode() != "proxy" && cfg.TransportMode() != "direct" && cfg.TransportMode() != "luna-agent" {
		return nil, err
	}
	log.Printf("[SSH] transport.mode=%s", cfg.TransportMode())
	return &Pool{clients: make(map[string]*gossh.Client), auth: auth}, nil
}
```

Keep `NewPool()` as deprecated wrapper calling `NewPool(nil)` only in tests OR remove and fix call sites in same task.

- [ ] **Step 3: Update `getClient`**

Replace:

```go
signers, err := collectAuthSigners(host)
```

With:

```go
signers, err := p.signersFor(context.Background(), target)
```

Use request context later if MCP passes ctx (YAGNI v1: Background).

**Proxy-only rule:** `directAuth` is the only implementation that calls `sharedAgentSigners`; `proxyAuth` never does.

- [ ] **Step 4: Run full tests**

Run: `go test ./...`  
Expected: PASS (except integration)

- [ ] **Step 5: Commit**

```bash
git add internal/ssh/pool.go internal/ssh/pool_test.go
git commit -m "feat(ssh): pool obtains signers from AuthProvider before direct dial"
```

---

### Task 6: Wire entrypoints + startup validation

**Files:**
- Modify: `cmd/serve.go`, `cmd/ssh-debug/main.go`

- [ ] **Step 1: `serve.go`**

```go
if err := settings.ValidateTransport(); err != nil {
	log.Fatalf("config: %v", err)
}
pool, err := ssh.NewPool(settings)
if err != nil {
	log.Fatalf("ssh: %v", err)
}
```

- [ ] **Step 2: `ssh-debug`**

Load `config.LoadSettings()`, print `transport.mode` and `proxy.endpoint`, `pool, err := ssh.NewPool(settings)`.

- [ ] **Step 3: Manual smoke**

Run: `make build`  
Run: `./bin/luna serve` without endpoint — expect fatal about proxy endpoint.  
Run: with valid config + live proxy — `ssh-debug user@host` dials from local IP (verify on target).

- [ ] **Step 4: Commit**

```bash
git add cmd/serve.go cmd/ssh-debug/main.go
git commit -m "feat(cmd): validate transport config and use AuthProvider pool"
```

---

### Task 7: Tool-layer error text (if needed)

**Files:**
- Modify: `internal/tools/execute_remote.go` (only if errors are wrapped opaque)

- [ ] **Step 1: Check error propagation**

Run mutating tool against denied access — MCP text should include `ACCESS_DENIED:`.

If `pool.Execute` wraps with `SSH execution error`, add:

```go
if msg := ssh.AccessErrorMessage(err); msg != "" {
	return mcp.NewToolResultText(msg), nil
}
```

Implement `AccessErrorMessage` in `access_errors.go`.

- [ ] **Step 2: Commit if changed**

```bash
git commit -m "fix(tools): surface ACCESS_* errors to MCP clients"
```

---

### Task 8: Documentation

**Files:**
- Modify: `README.md`, `docs/goclaw-integration.md`, `internal/ssh/AGENTS.md`, `AGENTS.md`
- Modify: `examples` or `.config/luna.config.json` example with `transport` block (no proxy telegram)

- [ ] **Step 1: README diagram**

Clarify: proxy signs; lunacli dials; two Telegram systems (proxy vs command).

- [ ] **Step 2: goclaw-integration.md**

Add trust boundary: goclaw never gets signed keys if separate user — interceptor user owns pool.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/goclaw-integration.md internal/ssh/AGENTS.md AGENTS.md
git commit -m "docs: luna-proxy signing and direct SSH dial"
```

---

## Plan self-review

| Spec requirement | Task |
|------------------|------|
| SDK in-process + replace | Task 0 |
| Default `proxy` mode | Task 1 |
| Proxy signs; lunacli dials | Tasks 4–5 |
| Proxy-only signers in proxy mode | Tasks 4–5 (`proxyAuth` only) |
| No proxy Telegram in lunacli config | Tasks 1, 8 |
| Command approval unchanged | No approval tasks |
| Opt-in direct/agent + warnings | Task 2 |
| All entrypoints | Task 6 |
| ACCESS_* errors | Tasks 3, 7 |
| ssh-debug | Task 6 |

No TBD steps. SDK type names in Task 4 adapt once Task 0 reads real `luna-sdk`.

---

## Manual test checklist

- [ ] Proxy access Telegram fires before first dial; command Telegram still separate for mutating ops.
- [ ] Target `sshd` / `auth.log` shows **lunacli host IP**, not proxy, on SSH connect.
- [ ] `transport.mode=direct` logs warning and uses local agent keys.
- [ ] `go test ./...` and `make lint` pass.
