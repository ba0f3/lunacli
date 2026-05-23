# Luna `onboard` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `luna onboard`, an interactive subcommand that writes `luna.config.json`, unpacks embedded gzip-tar policy files (`policy.yml` + skeleton `hosts.yml`), and completes Telegram setup including `getUpdates`-based approver discovery.

**Architecture:** Thin `cmd/onboard.go` delegates to `internal/onboard.Runner`. Bundle built via `go generate` into checked-in `bundle.tar.gz` and `//go:embed`. Stdio prompts without new UI dependencies. Telegram discovery uses a small HTTP client in `internal/onboard/telegram.go` (minimal JSON types; does not change serve poll `allowed_updates`).

**Tech Stack:** Go 1.25+, `cobra`, `archive/tar`, `compress/gzip`, `go:embed`, `gopkg.in/yaml.v3` (skeleton only in source), existing `internal/config` types for JSON shape.

**Spec:** [docs/superpowers/specs/2026-05-23-luna-onboard-design.md](../specs/2026-05-23-luna-onboard-design.md)

---

## Resolved open items (from spec)

| Item | Decision |
|------|----------|
| `bundle.tar.gz` | **Checked in** under `internal/onboard/`; rebuilt via `go generate` / `make onboard-bundle` |
| User-wide `config_dir` in JSON | `"luna.d"` (resolves to `~/.config/luna/luna.d` via `Settings.ConfigDir()`) |
| Project-local `config_dir` | `"./luna.d"` |
| Token input | Plain `bufio` line read; stderr warns not to share screen |

---

## File map

| File | Responsibility |
|------|----------------|
| `cmd/onboard.go` | Cobra `onboard`, TTY gate, call `onboard.Run` |
| `internal/onboard/layout.go` | `Target`, `Layout` paths for user-wide vs project-local |
| `internal/onboard/layout_test.go` | Path resolution tests |
| `internal/onboard/bundle_src/policy.yml` | Copy of `examples/luna.d/policy.yml` (maintained at generate time) |
| `internal/onboard/bundle_src/hosts.yml` | Skeleton hosts only |
| `internal/onboard/gen_bundle.go` | `//go:generate` tarball builder |
| `internal/onboard/bundle.tar.gz` | **Generated artifact** (committed) |
| `internal/onboard/assets.go` | `//go:embed bundle.tar.gz` |
| `internal/onboard/bundle.go` | Safe tar.gz extract to directory |
| `internal/onboard/bundle_test.go` | Traversal + happy path tests |
| `internal/onboard/install.go` | `WriteMode`, `WriteFile`, `WriteJSON` |
| `internal/onboard/install_test.go` | Merge/replace tests |
| `internal/onboard/telegram.go` | Token file, `DiscoverApprover`, manual fallback |
| `internal/onboard/telegram_test.go` | httptest getUpdates |
| `internal/onboard/prompt.go` | Stdio choice + line prompts |
| `internal/onboard/runner.go` | `Run(in, out, errOut)` orchestration |
| `internal/onboard/runner_test.go` | Scripted stdin integration |
| `Makefile` | `onboard-bundle` target |
| `README.md` | Quick Start mentions `luna onboard` |
| `examples/luna.d/README.md` | Point to `luna onboard` |
| `cmd/AGENTS.md` | Document `onboard` subcommand |

---

### Task 1: Bundle source + code generation

**Files:**
- Create: `internal/onboard/bundle_src/hosts.yml`
- Create: `internal/onboard/gen_bundle.go`
- Create: `internal/onboard/bundle.tar.gz` (via generate)
- Modify: `Makefile`

- [ ] **Step 1: Add skeleton hosts**

Create `internal/onboard/bundle_src/hosts.yml`:

```yaml
version: 1
hosts:
  - alias: example-host
    host: user@hostname
    tags: []
    description: ""
```

- [ ] **Step 2: Copy policy into bundle_src**

```bash
cp examples/luna.d/policy.yml internal/onboard/bundle_src/policy.yml
```

- [ ] **Step 3: Add `gen_bundle.go`**

Create `internal/onboard/gen_bundle.go`:

```go
//go:build ignore

//go:generate go run gen_bundle.go

package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	const srcDir = "bundle_src"
	const out = "bundle.tar.gz"

	f, err := os.Create(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", out, err)
		os.Exit(1)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	entries := []string{"policy.yml", "hosts.yml"}
	for _, name := range entries {
		path := filepath.Join(srcDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(1)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(data)),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "header %s: %v\n", name, err)
			os.Exit(1)
		}
		if _, err := tw.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "body %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
}
```

Add at top of `internal/onboard/assets.go` (created in Task 2):

```go
//go:generate go run gen_bundle.go
```

- [ ] **Step 4: Makefile target**

Add to `Makefile`:

```makefile
onboard-bundle:
	cd internal/onboard && go run gen_bundle.go
```

- [ ] **Step 5: Generate and verify tarball**

```bash
make onboard-bundle
tar -tzf internal/onboard/bundle.tar.gz
```

Expected:

```
policy.yml
hosts.yml
```

- [ ] **Step 6: Commit**

```bash
git add internal/onboard/bundle_src internal/onboard/gen_bundle.go internal/onboard/bundle.tar.gz Makefile
git commit -m "chore(onboard): add embedded policy bundle source and tarball"
```

---

### Task 2: Safe bundle extract + embed

**Files:**
- Create: `internal/onboard/assets.go`
- Create: `internal/onboard/bundle.go`
- Create: `internal/onboard/bundle_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/onboard/bundle_test.go`:

```go
package onboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractBundle_safeAndWritesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractBundle(embeddedBundle, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"policy.yml", "hosts.yml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
	}
}

func TestExtractBundle_rejectsTraversal(t *testing.T) {
	bad, err := tarGzBytes([]tarEntry{{Name: "../evil", Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtractBundle(bad, t.TempDir()); err == nil {
		t.Fatal("expected error for path traversal")
	}
}

type tarEntry struct {
	Name string
	Data []byte
}

func tarGzBytes(entries []tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.Name, Mode: 0644, Size: int64(len(e.Data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 2: Run test — expect fail**

```bash
go test ./internal/onboard/ -run ExtractBundle -v
```

Expected: compile error (`ExtractBundle`, `embeddedBundle` undefined)

- [ ] **Step 3: Implement embed + extract**

`internal/onboard/assets.go`:

```go
package onboard

import _ "embed"

//go:generate go run gen_bundle.go

//go:embed bundle.tar.gz
var embeddedBundle []byte
```

`internal/onboard/bundle.go`:

```go
package onboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractBundle unpacks a gzip tarball into destDir (only policy.yml and hosts.yml).
func ExtractBundle(bundle []byte, destDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if err := validateTarName(hdr.Name); err != nil {
			return err
		}
		dest := filepath.Join(destDir, hdr.Name)
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
}

func validateTarName(name string) error {
	name = filepath.Clean(name)
	if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
		return fmt.Errorf("invalid tar entry: %q", name)
	}
	switch name {
	case "policy.yml", "hosts.yml":
		return nil
	default:
		return fmt.Errorf("unexpected tar entry: %q", name)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/onboard/ -run ExtractBundle -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/onboard/assets.go internal/onboard/bundle.go internal/onboard/bundle_test.go
git commit -m "feat(onboard): embed and safely extract policy bundle"
```

---

### Task 3: Layout paths

**Files:**
- Create: `internal/onboard/layout.go`
- Create: `internal/onboard/layout_test.go`

- [ ] **Step 1: Write failing tests**

```go
package onboard

import (
	"path/filepath"
	"testing"
)

func TestLayout_userWide(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ly, err := NewLayout(TargetUserWide)
	if err != nil {
		t.Fatal(err)
	}
	wantConfig := filepath.Join(home, ".config", "luna", "luna.config.json")
	if ly.ConfigJSON != wantConfig {
		t.Errorf("ConfigJSON = %q, want %q", ly.ConfigJSON, wantConfig)
	}
	if ly.ConfigDirRel != "luna.d" {
		t.Errorf("ConfigDirRel = %q", ly.ConfigDirRel)
	}
	if ly.PolicyDir != filepath.Join(home, ".config", "luna", "luna.d") {
		t.Errorf("PolicyDir = %q", ly.PolicyDir)
	}
}

func TestLayout_projectLocal(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ly, err := NewLayout(TargetProjectLocal)
	if err != nil {
		t.Fatal(err)
	}
	if ly.ConfigJSON != filepath.Join(dir, "luna.config.json") {
		t.Errorf("ConfigJSON = %q", ly.ConfigJSON)
	}
	if ly.ConfigDirRel != "./luna.d" {
		t.Errorf("ConfigDirRel = %q", ly.ConfigDirRel)
	}
	if ly.PolicyDir != filepath.Join(dir, "luna.d") {
		t.Errorf("PolicyDir = %q", ly.PolicyDir)
	}
}
```

- [ ] **Step 2: Run test — fail**

```bash
go test ./internal/onboard/ -run TestLayout -v
```

- [ ] **Step 3: Implement**

```go
package onboard

import (
	"fmt"
	"os"
	"path/filepath"
)

type Target int

const (
	TargetUserWide Target = iota
	TargetProjectLocal
)

type Layout struct {
	ConfigJSON    string
	ConfigRoot    string
	ConfigDirRel  string
	PolicyDir     string
	TokenFile     string
}

func NewLayout(target Target) (Layout, error) {
	switch target {
	case TargetUserWide:
		home, err := os.UserHomeDir()
		if err != nil {
			return Layout{}, err
		}
		root := filepath.Join(home, ".config", "luna")
		return Layout{
			ConfigJSON:   filepath.Join(root, "luna.config.json"),
			ConfigRoot:   root,
			ConfigDirRel: "luna.d",
			PolicyDir:    filepath.Join(root, "luna.d"),
			TokenFile:    filepath.Join(root, "telegram-bot-token"),
		}, nil
	case TargetProjectLocal:
		cwd, err := os.Getwd()
		if err != nil {
			return Layout{}, err
		}
		return Layout{
			ConfigJSON:   filepath.Join(cwd, "luna.config.json"),
			ConfigRoot:   cwd,
			ConfigDirRel: "./luna.d",
			PolicyDir:    filepath.Join(cwd, "luna.d"),
			TokenFile:    filepath.Join(cwd, "telegram-bot-token"),
		}, nil
	default:
		return Layout{}, fmt.Errorf("unknown target %d", target)
	}
}

func (l Layout) BundleFiles() map[string]string {
	return map[string]string{
		filepath.Join(l.PolicyDir, "policy.yml"): "policy.yml",
		filepath.Join(l.PolicyDir, "hosts.yml"):   "hosts.yml",
	}
}
```

- [ ] **Step 4: Run tests — PASS**

- [ ] **Step 5: Commit**

```bash
git add internal/onboard/layout.go internal/onboard/layout_test.go
git commit -m "feat(onboard): resolve user-wide and project-local paths"
```

---

### Task 4: Install helpers (merge / replace)

**Files:**
- Create: `internal/onboard/install.go`
- Create: `internal/onboard/install_test.go`

- [ ] **Step 1: Write failing tests**

```go
package onboard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile_mergeSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	wrote, err := WriteFile(WriteMerge, p, []byte("new"), 0644)
	if err != nil || wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "old" {
		t.Fatalf("content = %q", b)
	}
}

func TestWriteFile_replaceOverwrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	_ = os.WriteFile(p, []byte("old"), 0644)
	wrote, err := WriteFile(WriteReplace, p, []byte("new"), 0644)
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
}
```

- [ ] **Step 2: Implement**

```go
package onboard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ba0f3/lunacli/internal/config"
)

type WriteMode int

const (
	WriteMerge WriteMode = iota
	WriteReplace
)

func WriteFile(mode WriteMode, path string, data []byte, perm os.FileMode) (bool, error) {
	if mode == WriteMerge {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return false, err
	}
	return true, nil
}

func WriteConfigJSON(path string, mode WriteMode, fs config.FileSettings) (bool, error) {
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	return WriteFile(mode, path, data, 0644)
}
```

- [ ] **Step 3: Run tests — PASS**

- [ ] **Step 4: Commit**

```bash
git add internal/onboard/install.go internal/onboard/install_test.go
git commit -m "feat(onboard): merge and replace file writes"
```

---

### Task 5: Telegram discovery

**Files:**
- Create: `internal/onboard/telegram.go`
- Create: `internal/onboard/telegram_test.go`

- [ ] **Step 1: Write failing test**

```go
package onboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverApprover_fromMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bottok/getUpdates" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"from":{"id":4242},"chat":{"id":9999},"text":"/start"}}]}`))
	}))
	defer srv.Close()

	approver, chat, err := DiscoverApprover(context.Background(), "tok", srv.Client(), srv.URL+"/bot%s/")
	if err != nil {
		t.Fatal(err)
	}
	if approver != "4242" || chat != "9999" {
		t.Fatalf("approver=%s chat=%s", approver, chat)
	}
}
```

- [ ] **Step 2: Implement**

```go
package onboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func SaveBotToken(path, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("empty bot token")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token+"\n"), 0600)
}

// DiscoverApprover polls getUpdates for a user message (e.g. /start).
// apiBaseFmt is like "https://api.telegram.org/bot%s/" (trailing slash optional).
func DiscoverApprover(ctx context.Context, token string, client *http.Client, apiBaseFmt string) (approverID, chatID string, err error) {
	if client == nil {
		client = http.DefaultClient
	}
	if apiBaseFmt == "" {
		apiBaseFmt = "https://api.telegram.org/bot%s/"
	}
	base := fmt.Sprintf(apiBaseFmt, token)
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	url := base + "getUpdates"

	deadline := time.Now().Add(2 * time.Minute)
	var lastUpdateID int64
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		body := map[string]any{
			"timeout":         25,
			"offset":          lastUpdateID + 1,
			"allowed_updates": []string{"message"},
		}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", "", err
		}
		var parsed telegramUpdatesResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return "", "", err
		}
		if !parsed.OK {
			return "", "", fmt.Errorf("telegram getUpdates: %s", parsed.Description)
		}
		for _, u := range parsed.Result {
			if u.UpdateID > lastUpdateID {
				lastUpdateID = u.UpdateID
			}
			if u.Message != nil && u.Message.From != nil {
				return strconv.FormatInt(u.Message.From.ID, 10),
					strconv.FormatInt(u.Message.Chat.ID, 10), nil
			}
		}
	}
	return "", "", fmt.Errorf("no Telegram message received; send /start to your bot and retry")
}

type telegramUpdatesResponse struct {
	OK          bool             `json:"ok"`
	Description string           `json:"description"`
	Result      []telegramUpdate `json:"result"`
}

type telegramUpdate struct {
	UpdateID int64            `json:"update_id"`
	Message  *telegramMessage `json:"message,omitempty"`
}

type telegramMessage struct {
	From *telegramUser `json:"from"`
	Chat telegramChat  `json:"chat"`
	Text string        `json:"text"`
}

type telegramUser struct {
	ID int64 `json:"id"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}
```

- [ ] **Step 3: Run test — PASS**

```bash
go test ./internal/onboard/ -run DiscoverApprover -v
```

- [ ] **Step 4: Commit**

```bash
git add internal/onboard/telegram.go internal/onboard/telegram_test.go
git commit -m "feat(onboard): telegram token file and approver discovery"
```

---

### Task 6: Prompts + runner

**Files:**
- Create: `internal/onboard/prompt.go`
- Create: `internal/onboard/runner.go`
- Create: `internal/onboard/runner_test.go`

- [ ] **Step 1: Write runner integration test (scripted stdin)**

```go
func TestRun_userWide_merge_writesPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	in := strings.NewReader("1\n1\n\n") // user-wide, merge, skip token/discovery — split test
	// Full Run test deferred: test InstallBundle helper instead
}
```

Prefer testing `installBundle` exported helper after refactor. Minimal test:

```go
func TestInstallBundle_merge(t *testing.T) {
	ly, _ := NewLayout(TargetUserWide)
	// ... WriteMerge + ExtractBundle into ly.PolicyDir
}
```

- [ ] **Step 2: Implement `prompt.go`**

```go
package onboard

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type Prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func NewPrompter(in io.Reader, out io.Writer) *Prompter {
	return &Prompter{in: bufio.NewReader(in), out: out}
}

func (p *Prompter) Choice(prompt string, options []string, defaultIdx int) (int, error) {
	for i, o := range options {
		d := ""
		if i == defaultIdx {
			d = " [default]"
		}
		fmt.Fprintf(p.out, "  %d) %s%s\n", i+1, o, d)
	}
	fmt.Fprintf(p.out, "%s [%d]: ", prompt, defaultIdx+1)
	line, err := p.in.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultIdx, nil
	}
	var n int
	if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(options) {
		return defaultIdx, nil
	}
	return n - 1, nil
}

func (p *Prompter) Line(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	line, err := p.in.ReadString('\n')
	return strings.TrimSpace(line), err
}
```

- [ ] **Step 3: Implement `runner.go`**

Order of operations:

1. Welcome text + docs link
2. `Choice` target (default user-wide)
3. `Choice` merge vs replace
4. `MkdirAll` policy dir
5. `ExtractBundle` → write each file with `WriteFile` (merge/replace)
6. Prompt token (warn shoulder-surfing) → `SaveBotToken`
7. Guide `/start` → `DiscoverApprover` (retry once) → manual `Line` fallback for approver id; chat defaults to approver
8. `WriteConfigJSON` with `config.FileSettings` populated
9. Print summary + MCP JSON with `os.Executable()`

```go
func Run(in io.Reader, out, errOut io.Writer) error {
	if !stdinIsTerminal() {
		return fmt.Errorf("onboard requires an interactive terminal")
	}
	// ... orchestration
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
```

- [ ] **Step 4: Run package tests**

```bash
go test ./internal/onboard/ -v
```

- [ ] **Step 5: Commit**

```bash
git add internal/onboard/prompt.go internal/onboard/runner.go internal/onboard/runner_test.go
git commit -m "feat(onboard): interactive runner and prompts"
```

---

### Task 7: Cobra command

**Files:**
- Create: `cmd/onboard.go`
- Modify: `cmd/AGENTS.md`

- [ ] **Step 1: Add command**

```go
package cmd

import (
	"os"

	"github.com/ba0f3/lunacli/internal/onboard"
	"github.com/spf13/cobra"
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Interactive setup for Luna config, policy, and Telegram",
	RunE: func(cmd *cobra.Command, args []string) error {
		return onboard.Run(os.Stdin, os.Stdout, os.Stderr)
	},
}

func init() {
	RootCmd.AddCommand(onboardCmd)
}
```

- [ ] **Step 2: Build and smoke (manual)**

```bash
make build
./bin/luna onboard --help
```

- [ ] **Step 3: Commit**

```bash
git add cmd/onboard.go cmd/AGENTS.md
git commit -m "feat(cli): add luna onboard subcommand"
```

---

### Task 8: Documentation

**Files:**
- Modify: `README.md`
- Modify: `examples/luna.d/README.md`

- [ ] **Step 1: README Quick Start**

After "### 2. Configure", add:

```markdown
Or run interactive setup:

```bash
./bin/luna onboard
```

This writes `luna.config.json`, `luna.d/policy.yml`, skeleton `hosts.yml`, and configures Telegram.
```

- [ ] **Step 2: examples README**

Replace manual `cp` block intro with: "Run `luna onboard` or copy manually:"

- [ ] **Step 3: Commit**

```bash
git add README.md examples/luna.d/README.md
git commit -m "docs: document luna onboard setup flow"
```

---

### Task 9: Verify end-to-end

- [ ] **Step 1: Full test suite**

```bash
make test
make lint
```

Expected: all pass

- [ ] **Step 2: Config resolution check**

After manual `luna onboard` (user-wide) in temp `HOME`:

```bash
HOME=$(mktemp -d) ./bin/luna onboard
# complete flow with test bot or mock — optional
LUNA_CONFIG_DIR= go test ./internal/config/ -run ConfigDir -v
```

Add `internal/onboard/layout_test.go` case: write policy + load `config.LoadSettings` from home — optional follow-up test:

```go
func TestLayout_serveFindsPolicy(t *testing.T) {
	// write policy.yml under ly.PolicyDir, write luna.config.json, LoadSettings().ConfigDir() has policy
}
```

- [ ] **Step 3: Update spec status**

In `docs/superpowers/specs/2026-05-23-luna-onboard-design.md`, set **Status** to `Plan ready — see plans/2026-05-23-luna-onboard.md`.

- [ ] **Step 4: Final commit (if spec status changed)**

```bash
git add docs/superpowers/specs/2026-05-23-luna-onboard-design.md
git commit -m "docs: link onboard spec to implementation plan"
```

---

## Spec coverage checklist

| Spec requirement | Task |
|------------------|------|
| `luna onboard` interactive only | Task 7, runner TTY check |
| Location choice, default user-wide | Task 3, 6 |
| Merge vs replace | Task 4, 6 |
| Embedded gzip tar policy + skeleton hosts | Task 1, 2 |
| Telegram token file 0600 | Task 5 |
| getUpdates discovery + manual fallback | Task 5, 6 |
| No env.example / no automation flags | — (omitted by design) |
| Docs updates | Task 8 |
| Success criteria (serve-ready layout) | Task 9 |

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-23-luna-onboard.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — implement task-by-task in this session with checkpoints  

Which approach do you want?
