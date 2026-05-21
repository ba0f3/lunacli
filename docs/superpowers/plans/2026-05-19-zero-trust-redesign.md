# Luna Zero-Trust Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the Luna interceptor into a dual-mode zero-trust CLI and stdio MCP server with configurable YAML policy controls, out-of-band approval verification, structured audit logging, and fleet execution.

**Architecture:** Split the codebase into logical packages under `internal/`: `engine` for Go/YAML hybrid classification, `policy` for loader and matching rules, `config` for hosts/policy file resolutions, `audit` for structured JSON output, `fleet` for tag-based async orchestration, and `cmd` for Cobra CLI dispatch. All mutations strictly require out-of-band human approval (no self-approval).

**Tech Stack:** Go 1.25.5, `github.com/spf13/cobra`, `gopkg.in/yaml.v3`, `github.com/mark3labs/mcp-go`, SQLite via `modernc.org/sqlite`.

---

## File Structure & Dependencies

- **Modify** `interceptor/go.mod` to add `github.com/spf13/cobra` and `gopkg.in/yaml.v3`
- **Create** `interceptor/internal/config/config.go` and `hosts.go` for resolving config directories and parsing `hosts.yml`.
- **Create** `interceptor/internal/policy/types.go` and `loader.go` for parsing and loading `policy.yml`.
- **Create** `interceptor/internal/engine/engine.go` and `hardcoded.go` for running Layer 1 (immutable compiled Go patterns) + Layer 2 (YAML overlay) engine logic.
- **Modify** `interceptor/internal/approval/gate.go` and `service.go` to remove `ModeLocal` and local `allow_mutations` parameter. Everything is strictly out-of-band.
- **Create** `interceptor/internal/audit/logger.go` to support dual structured JSON output (stderr + file).
- **Create** `interceptor/internal/fleet/executor.go` and `async.go` to manage tag-based fleet runs and ephemeral async tasks.
- **Create** `interceptor/cmd/` package containing Cobra commands for serve, exec, plan, approvals, audit, hosts, and policy.
- **Modify** `interceptor/main.go` to serve as a lightweight entrypoint that delegates completely to `cmd.Execute()`.
- **Modify** `interceptor/internal/tools/` package files to register the new zero-trust fleet and planning tools.

---

## Phase 1: Configuration & YAML Loader

### Task 1.1: Initialize Dependencies and Config Package

**Files:**
- Modify: `interceptor/go.mod`
- Create: `interceptor/internal/config/config.go`
- Create: `interceptor/internal/config/hosts.go`
- Create: `interceptor/internal/config/hosts_test.go`

- [ ] **Step 1: Update go.mod with Cobra and YAML dependencies**

Edit `interceptor/go.mod` to include:
```go
require (
	github.com/spf13/cobra v1.8.0
	gopkg.in/yaml.v3 v3.0.1
)
```

- [ ] **Step 2: Run go mod tidy**

Run: `cd interceptor && go mod tidy`

- [ ] **Step 3: Implement Config Directory Resolution and Hosts Parser**

Create `interceptor/internal/config/config.go`:
```go
package config

import (
	"os"
	"path/filepath"
)

func ResolveConfigDir() string {
	if dir := os.Getenv("LUNA_CONFIG_DIR"); dir != "" {
		return dir
	}
	if _, err := os.Stat("./luna.d"); err == nil {
		return "./luna.d"
	}
	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".config", "luna")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "/etc/luna"
}
```

Create `interceptor/internal/config/hosts.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"gopkg.in/yaml.v3"
)

type HostEntry struct {
	Alias       string   `yaml:"alias"`
	Host        string   `yaml:"host"`
	Tags        []string `yaml:"tags"`
	Description string   `yaml:"description"`
}

type HostsConfig struct {
	Version int         `yaml:"version"`
	Hosts   []HostEntry `yaml:"hosts"`
}

func LoadHosts(dir string) (*HostsConfig, error) {
	path := filepath.Join(dir, "hosts.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &HostsConfig{Version: 1, Hosts: []HostEntry{}}, nil
		}
		return nil, err
	}
	var cfg HostsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

- [ ] **Step 4: Create Hosts Parser Tests**

Create `interceptor/internal/config/hosts_test.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHosts(t *testing.T) {
	tmp, err := os.MkdirTemp("", "luna-hosts-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	content := `
version: 1
hosts:
  - alias: test-prod
    host: root@10.0.0.1
    tags: [prod, web]
    description: "test host"
`
	if err := os.WriteFile(filepath.Join(tmp, "hosts.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadHosts(tmp)
	if err != nil {
		t.Fatalf("failed to load hosts: %v", err)
	}
	if len(cfg.Hosts) != 1 || cfg.Hosts[0].Alias != "test-prod" {
		t.Errorf("unexpected loaded hosts: %+v", cfg)
	}
}
```

- [ ] **Step 5: Run Tests to Verify Config Package**

Run: `cd interceptor && go test -v ./internal/config/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add interceptor/go.mod interceptor/go.sum interceptor/internal/config
git commit -m "feat(config): add hosts loader and directory resolver"
```

### Task 1.2: Implement policy.yml Loader and Matches

**Files:**
- Create: `interceptor/internal/policy/types.go`
- Create: `interceptor/internal/policy/loader.go`
- Create: `interceptor/internal/policy/loader_test.go`

- [ ] **Step 1: Create Policy Struct Definition**

Create `interceptor/internal/policy/types.go`:
```go
package policy

type CommandRule struct {
	Binary     string   `yaml:"binary"`
	ArgsPrefix []string `yaml:"args_prefix"`
}

type Rule struct {
	Action   string        `yaml:"action"` // allow, approve, deny
	Hosts    []string      `yaml:"hosts"`
	Tags     []string      `yaml:"tags"`
	Commands []CommandRule `yaml:"commands"`
}

type Policy struct {
	Version      int      `yaml:"version"`
	DenyPatterns []string `yaml:"deny_patterns"`
	Rules        []Rule   `yaml:"rules"`
}
```

- [ ] **Step 2: Implement Loader and Loader Tests**

Create `interceptor/internal/policy/loader.go`:
```go
package policy

import (
	"os"
	"path/filepath"
	"gopkg.in/yaml.v3"
)

func LoadPolicy(dir string) (*Policy, error) {
	path := filepath.Join(dir, "policy.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}
```

Create `interceptor/internal/policy/loader_test.go`:
```go
package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicy(t *testing.T) {
	tmp, err := os.MkdirTemp("", "luna-policy-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	content := `
version: 1
deny_patterns:
  - "curl.*--upload-file"
rules:
  - action: allow
    hosts: ["*"]
    tags: ["*"]
    commands:
      - binary: uptime
      - binary: ls
        args_prefix: ["-lh"]
`
	if err := os.WriteFile(filepath.Join(tmp, "policy.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pol, err := LoadPolicy(tmp)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	if len(pol.DenyPatterns) != 1 || len(pol.Rules) != 1 {
		t.Errorf("unexpected loaded policy: %+v", pol)
	}
}
```

- [ ] **Step 3: Run Policy Package Tests**

Run: `cd interceptor && go test -v ./internal/policy/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add interceptor/internal/policy
git commit -m "feat(policy): add YAML policy schema and loader"
```

---

## Phase 2: Engine Split & Hybrid Classification

### Task 2.1: Implement Engine Classification Logic

**Files:**
- Create: `interceptor/internal/engine/engine.go`
- Create: `interceptor/internal/engine/hardcoded.go`
- Create: `interceptor/internal/engine/engine_test.go`
- Modify: `interceptor/internal/security/allowlist.go`

- [ ] **Step 1: Re-use Immutable Rules from allowlist.go**

Copy the `forbiddenPatterns` and helper methods like `unescape`, `unwrapCommand`, and `isDatabaseMutation` into `interceptor/internal/engine/hardcoded.go`. We also bring along `mutatingFlagPatterns`.

Create `interceptor/internal/engine/hardcoded.go`:
```go
package engine

import (
	"path/filepath"
	"regexp"
	"strings"
)

const maxCommandLen = 4096

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*|-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+/(?:\s+|$)`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)>\s*/dev/sd[a-z]`),
	regexp.MustCompile(`(?i)>\s*/dev/nvme`),
	regexp.MustCompile(`(?i)>\s*/dev/hd[a-z]`),
	regexp.MustCompile(`(?i)>\s*/dev/mapper/`),
	regexp.MustCompile(`(?i)\bshred\b`),
	regexp.MustCompile(`(?i)\bwipefs\b`),
	regexp.MustCompile(`(?i)\bfdisk\b`),
	regexp.MustCompile(`(?i)\bparted\b`),
	regexp.MustCompile(`(?i)\bcrypt\w*\s+luksFormat`),
	regexp.MustCompile(`(?i)\bdebugfs\b`),
	regexp.MustCompile(`(?i)\btune2fs\b`),
	regexp.MustCompile(`(?i)\bresize2fs\b`),
	regexp.MustCompile(`(?i)\bxfs_growfs\b`),
	regexp.MustCompile(`(?i)\bfsck\b`),
	regexp.MustCompile(`(?i)\bbadblocks\b`),
	regexp.MustCompile(`(?i)\bhdparm\b`),
	regexp.MustCompile(`(?i):\(\)\s*\{`),
	regexp.MustCompile(`(?i)\biptables\s+-F\b`),
	regexp.MustCompile(`(?i)\bnft\s+flush\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])passwd\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])(?:useradd|userdel|usermod)\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])(?:groupadd|groupdel|groupmod)\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])visudo\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])sudo\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])su\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])doas\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])insmod\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])modprobe\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])rmmod\b`),
	regexp.MustCompile(`(?i)\bnc\s+.*-[el]`),
	regexp.MustCompile(`(?i)\bncat\s+.*-[el]`),
	regexp.MustCompile(`(?i)\bsocat\b`),
	regexp.MustCompile(`(?i)/dev/tcp/`),
	regexp.MustCompile(`(?i)/dev/udp/`),
	regexp.MustCompile(`(?i)\bbash\s+-i\b`),
	regexp.MustCompile(`(?i)\bpython[23]?\s+.*-[ci]\b`),
	regexp.MustCompile(`(?i)\bperl\s+(?:.*?\s)?-[a-z]*[ei][^\s]*(?:\s|$)`),
	regexp.MustCompile(`(?i)\bruby\s+.*-[ei]\b`),
	regexp.MustCompile(`(?i)\bnode\s+.*-[ei]\b`),
	regexp.MustCompile(`(?i)\blua\b`),
	regexp.MustCompile(`(?i)^python[23]?\s+\S`),
	regexp.MustCompile(`(?i)^ruby\s+\S`),
	regexp.MustCompile(`(?i)^node\s+\S`),
	regexp.MustCompile(`(?i)^perl\s+\S`),
	regexp.MustCompile(`(?i)^php\s+\S`),
	regexp.MustCompile(`(?i)^Rscript\s+\S`),
	regexp.MustCompile(`(?i)^(?:bash|sh|dash|zsh|ksh|csh|tcsh)\s+\S`),
	regexp.MustCompile(`(?i)^exec\s+\S`),
	regexp.MustCompile(`(?i)\bfind\s+.*-delete\b`),
	regexp.MustCompile(`(?i)\bfind\s+.*-exec\s+rm\b`),
	regexp.MustCompile(`(?i)\bchmod\s+(?:[0-7]*777|[0-7]*777[0-7]*)\s+/(?:etc|bin|sbin|usr)\b`),
	regexp.MustCompile(`(?i)\btee\s+/(?:etc/passwd|etc/shadow|etc/sudoers|etc/ssh)\b`),
}

var mutatingFlagPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bcurl\s+.*(?:-[A-Za-z]*d|--data|--data-binary|--data-raw|--data-urlencode|--post-file|-T\s|--upload-file)\b`),
	regexp.MustCompile(`(?i)\bcurl\s+.*(?:-o\s|--output|-O)\b`),
	regexp.MustCompile(`(?i)\bwget\s+.*(?:--post-data|--post-file|--body-data|--body-file|-O\s|--output-document)\b`),
	regexp.MustCompile(`(?i)\bfind\s+.*-(?:exec|ok)\b`),
	regexp.MustCompile(`(?i)\bsed\s+(?:.*?\s)?(?:-[a-z]*i[^\s]*|--in-place)(?:\s|$)`),
	regexp.MustCompile(`(?i)\bawk\s+(?:.*?\s)?-[a-z]*i[^\s]*(?:\s|$)`),
}

var databaseClients = map[string]struct{}{
	"clickhouse-client": {}, "duckdb": {}, "mariadb": {}, "mongo": {}, "mongosh": {},
	"mysql": {}, "psql": {}, "sqlite": {}, "sqlite3": {},
}
var databaseMutationPattern = regexp.MustCompile(`(?i)\b(?:update|delete\s+from|drop|create)\b`)

func unescape(s string) string {
	var b strings.Builder
	escaping := false
	for _, ch := range s {
		if escaping {
			b.WriteRune(ch)
			escaping = false
		} else if ch == '\\' {
			escaping = true
		} else {
			b.WriteRune(ch)
		}
	}
	if escaping {
		b.WriteRune('\\')
	}
	return b.String()
}

func unwrapCommand(args []string) []string {
	if len(args) == 0 {
		return args
	}
	for {
		if len(args) == 0 {
			return args
		}
		cmd := args[0]
		if cmd == "env" {
			i := 1
			for i < len(args) {
				arg := args[i]
				if strings.Contains(arg, "=") {
					i++
					continue
				}
				if strings.HasPrefix(arg, "-") {
					i++
					continue
				}
				break
			}
			if i >= len(args) {
				return args
			}
			args = args[i:]
			continue
		}
		if cmd == "xargs" {
			i := 1
			for i < len(args) {
				arg := args[i]
				if strings.HasPrefix(arg, "-") {
					i++
					continue
				}
				break
			}
			if i >= len(args) {
				return args
			}
			args = args[i:]
			continue
		}
		break
	}
	return args
}

func isDatabaseMutation(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if _, ok := databaseClients[filepath.Base(strings.ToLower(args[0]))]; !ok {
		return false
	}
	for _, arg := range args[1:] {
		if databaseMutationPattern.MatchString(arg) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Create the Engine Classification Code**

Create `interceptor/internal/engine/engine.go`:
```go
package engine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ba0f3/lunacli/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

type Classification string

const (
	ReadOnly   Classification = "read-only"
	Mutating   Classification = "mutating"
	Forbidden  Classification = "forbidden"
)

type Result struct {
	Class  Classification
	Reason string
}

type Engine struct {
	pol *policy.Policy
}

func NewEngine(pol *policy.Policy) *Engine {
	return &Engine{pol: pol}
}

func (e *Engine) Classify(command string, host string, tags []string) Result {
	cmd := strings.TrimSpace(command)
	if len(cmd) > maxCommandLen {
		return Result{Class: Forbidden, Reason: "command exceeds maximum length"}
	}

	// Layer 1: Immutable checks on raw string
	for _, re := range forbiddenPatterns {
		if re.MatchString(cmd) {
			return Result{Class: Forbidden, Reason: "command matches compiled forbidden pattern"}
		}
	}

	p := syntax.NewParser()
	file, err := p.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return Result{Class: Mutating, Reason: "syntax error, treated as mutating by default"}
	}

	var res Result
	res.Class = ReadOnly

	flag := func(c Classification, reason string) {
		if c == Forbidden {
			res.Class = Forbidden
			res.Reason = reason
		} else if c == Mutating && res.Class != Forbidden {
			res.Class = Mutating
			res.Reason = reason
		}
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if res.Class == Forbidden {
			return false
		}
		switch x := node.(type) {
		case *syntax.Redirect:
			if strings.Contains(x.Op.String(), ">") {
				flag(Mutating, "command contains output redirection")
			}
		case *syntax.CmdSubst, *syntax.ProcSubst:
			flag(Mutating, "command contains substitution")
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}
			var args []string
			for _, arg := range x.Args {
				var b strings.Builder
				isStatic := true
				for _, part := range arg.Parts {
					switch p := part.(type) {
					case *syntax.Lit:
						b.WriteString(unescape(p.Value))
					case *syntax.SglQuoted:
						b.WriteString(p.Value)
					case *syntax.DblQuoted:
						for _, dp := range p.Parts {
							if dpl, ok := dp.(*syntax.Lit); ok {
								b.WriteString(unescape(dpl.Value))
							} else {
								isStatic = false
							}
						}
					default:
						isStatic = false
					}
				}
				if isStatic {
					args = append(args, b.String())
				} else {
					args = append(args, "<DYNAMIC>")
				}
			}

			if args[0] == "<DYNAMIC>" {
				flag(Mutating, "dynamic command")
				return true
			}

			args[0] = filepath.Base(args[0])
			args = unwrapCommand(args)
			if len(args) == 0 {
				flag(Mutating, "empty wrapped command")
				return true
			}
			args[0] = filepath.Base(args[0])
			unquotedCmd := strings.Join(args, " ")
			lowerCmd := strings.ToLower(unquotedCmd)

			for _, re := range forbiddenPatterns {
				if re.MatchString(unquotedCmd) {
					flag(Forbidden, "command matches compiled forbidden pattern")
					return false
				}
			}

			for _, re := range mutatingFlagPatterns {
				if re.MatchString(lowerCmd) {
					flag(Mutating, "command contains mutating flags")
					return true
				}
			}

			if isDatabaseMutation(args) {
				flag(Mutating, "database mutation statement")
				return true
			}

			// Layer 2: Match against policy overlay
			if e.pol != nil {
				// Evaluate custom policy deny_patterns
				for _, pat := range e.pol.DenyPatterns {
					if matched, _ := regexp.MatchString(pat, cmd); matched {
						flag(Forbidden, fmt.Sprintf("command matches policy deny pattern: %q", pat))
						return false
					}
				}

				// Evaluate custom policy rules
				matched := false
				for _, rule := range e.pol.Rules {
					if !matchHostOrTags(rule.Hosts, rule.Tags, host, tags) {
						continue
					}
					for _, rcmd := range rule.Commands {
						if rcmd.Binary == args[0] {
							if len(rcmd.ArgsPrefix) == 0 {
								matched = true
								actionClass := parseAction(rule.Action)
								flag(actionClass, fmt.Sprintf("matches rule with action %s", rule.Action))
								break
							}
							if matchesArgsPrefix(args[1:], rcmd.ArgsPrefix) {
								matched = true
								actionClass := parseAction(rule.Action)
								flag(actionClass, fmt.Sprintf("matches rule with action %s and args", rule.Action))
								break
							}
						}
					}
					if matched {
						break
					}
				}
				if !matched {
					flag(Mutating, "unrecognized command (deny-by-default)")
				}
			} else {
				flag(Mutating, "no policy configured, denying command")
			}
		}
		return true
	})

	return res
}

func parseAction(action string) Classification {
	switch action {
	case "allow":
		return ReadOnly
	case "approve":
		return Mutating
	case "deny":
		return Forbidden
	default:
		return Mutating
	}
}

func matchHostOrTags(hosts, tags []string, targetHost string, targetTags []string) bool {
	hostMatch := false
	for _, h := range hosts {
		if h == "*" || h == targetHost {
			hostMatch = true
			break
		}
	}
	if !hostMatch {
		return false
	}
	if len(tags) == 0 {
		return true
	}
	for _, t := range tags {
		if t == "*" {
			return true
		}
		for _, tt := range targetTags {
			if t == tt {
				return true
			}
		}
	}
	return false
}

func matchesArgsPrefix(args, prefixes []string) bool {
	if len(args) < len(prefixes) {
		return false
	}
	for i, pref := range prefixes {
		if args[i] != pref {
			return false
		}
	}
	return true
}
```

- [ ] **Step 3: Run Engine and Hybrid Tests**

Create `interceptor/internal/engine/engine_test.go`:
```go
package engine

import (
	"testing"
	"github.com/ba0f3/lunacli/internal/policy"
)

func TestEngineClassification(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Rules: []policy.Rule{
			{
				Action: "allow",
				Hosts:  []string{"*"},
				Commands: []policy.CommandRule{
					{Binary: "uptime"},
					{Binary: "ls", ArgsPrefix: []string{"-la"}},
				},
			},
			{
				Action: "approve",
				Hosts:  []string{"*"},
				Commands: []policy.CommandRule{
					{Binary: "systemctl", ArgsPrefix: []string{"restart"}},
				},
			},
		},
	}

	eng := NewEngine(pol)

	tests := []struct {
		cmd   string
		class Classification
	}{
		{"uptime", ReadOnly},
		{"ls -la /var/log", ReadOnly},
		{"systemctl restart nginx", Mutating},
		{"rm -rf /", Forbidden},
		{"unknown", Mutating}, // default deny
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			res := eng.Classify(tt.cmd, "localhost", nil)
			if res.Class != tt.class {
				t.Errorf("expected %s got %s", tt.class, res.Class)
			}
		})
	}
}
```

Run tests: `cd interceptor && go test -v ./internal/engine/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add interceptor/internal/engine
git commit -m "feat(engine): implement two-layer compiled/YAML hybrid engine"
```

---

## Phase 3: Out-of-Band Approvals System

### Task 3.1: Strip Local Allow Mutations and Env Mode

**Files:**
- Modify: `interceptor/internal/approval/mode.go`
- Modify: `interceptor/internal/approval/gate.go`
- Modify: `interceptor/internal/approval/service.go`

- [ ] **Step 1: Remove Local Mode from mode.go**

Modify `interceptor/internal/approval/mode.go` to remove `ModeLocal` entirely:
```go
package approval

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Store string
	TTL   time.Duration
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		TTL: 5 * time.Minute,
	}
	cfg.Store = strings.TrimSpace(os.Getenv("LUNA_APPROVAL_STORE"))
	if cfg.Store == "" {
		// default fallback path for sqlite
		cfg.Store = "approvals.db"
	}
	if ttlStr := strings.TrimSpace(os.Getenv("LUNA_APPROVAL_TTL")); ttlStr != "" {
		d, err := time.ParseDuration(ttlStr)
		if err != nil {
			return Config{}, fmt.Errorf("invalid LUNA_APPROVAL_TTL: %w", err)
		}
		cfg.TTL = d
	}
	return cfg, nil
}
```

- [ ] **Step 2: Simplify Gate Checks to be Strictly Out-of-Band**

Modify `interceptor/internal/approval/gate.go` to require OOB verification:
```go
package approval

import (
	"fmt"
	"time"
	"github.com/ba0f3/lunacli/internal/engine"
)

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

func (g *Gate) CheckExecuteRemote(check engine.Result, host, command string, timeoutSec float64, approvalID string) GateResult {
	if check.Class == engine.Forbidden {
		return GateResult{Kind: GateBlocked, BlockedText: "BLOCKED: " + check.Reason}
	}
	if check.Class == engine.ReadOnly {
		return GateResult{Kind: GateExecute}
	}

	// Strictly Out-of-Band remote approval verification (no local ModeLocal allowed)
	if g.svc == nil {
		return GateResult{
			Kind:           GatePermissionRequired,
			PermissionText: "PERMISSION_REQUIRED: approval database is not configured.",
		}
	}

	req, body, fp, err := BuildExecuteRemoteRequest(host, command, timeoutSec)
	if err != nil {
		return GateResult{
			Kind:           GatePermissionRequired,
			PermissionText: "PERMISSION_REQUIRED: error building approval: " + err.Error(),
		}
	}

	if approvalID != "" {
		if err := g.svc.VerifyAndConsume(approvalID, req, body, fp); err != nil {
			return GateResult{
				Kind:           GatePermissionRequired,
				PermissionText: fmt.Sprintf("PERMISSION_REQUIRED: approval consumed/invalid: %v", err),
				ApprovalID:     approvalID,
			}
		}
		return GateResult{Kind: GateExecute}
	}

	pending, err := g.svc.CreatePending(executeRemoteToolName, req, body, fp, string(check.Class), check.Reason)
	if err != nil {
		return GateResult{
			Kind:           GatePermissionRequired,
			PermissionText: "PERMISSION_REQUIRED: failed to register approval request: " + err.Error(),
		}
	}
	if g.providers != nil {
		_ = g.providers.NotifyAll(pending, req)
	}

	return GateResult{
		Kind:              GatePermissionRequired,
		PermissionText:    FormatPermissionRequired(check.Reason, req.Command, pending.ID, pending.ExpiresAt, pending.FingerprintPrefix),
		ApprovalID:        pending.ID,
		ExpiresAt:         pending.ExpiresAt,
		FingerprintPrefix: pending.FingerprintPrefix,
	}
}
```

- [ ] **Step 3: Run Approval Package Tests**

Run: `cd interceptor && go test -v ./internal/approval/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add interceptor/internal/approval
git commit -m "feat(approval): eliminate local self-approval and make OOB mandatory"
```

---

## Phase 4: Structured Audit Logging

### Task 4.1: Implement Dual Structured JSON Audit Logger

**Files:**
- Create: `interceptor/internal/audit/logger.go`
- Create: `interceptor/internal/audit/logger_test.go`

- [ ] **Step 1: Write JSON Lines Logger to stderr + file**

Create `interceptor/internal/audit/logger.go`:
```go
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	Timestamp      string `json:"timestamp"`
	Event          string `json:"event"`
	Host           string `json:"host,omitempty"`
	Command        string `json:"command,omitempty"`
	Classification string `json:"classification,omitempty"`
	ExitCode       int    `json:"exit_code,omitempty"`
	DurationMs     int64  `json:"duration_ms,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Source         string `json:"source"`
}

type Logger struct {
	mu       sync.Mutex
	filePath string
}

func NewLogger(filePath string) *Logger {
	return &Logger{filePath: filePath}
}

func (l *Logger) Log(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	// 1. Output to standard error (captured by logs aggregator)
	fmt.Fprintf(os.Stderr, "%s\n", string(data))

	// 2. Append to persistent audit file
	if l.filePath != "" {
		f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, _ = f.Write(data)
		_, _ = f.Write([]byte("\n"))
	}
	return nil
}
```

- [ ] **Step 2: Add Logger Tests**

Create `interceptor/internal/audit/logger_test.go`:
```go
package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogger(t *testing.T) {
	tmp, err := os.MkdirTemp("", "luna-audit-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	logFile := filepath.Join(tmp, "audit.jsonl")
	l := NewLogger(logFile)

	ev := Event{
		Event:          "command_executed",
		Host:           "10.0.0.1",
		Command:        "uptime",
		Classification: "read-only",
		Source:         "mcp",
	}

	if err := l.Log(ev); err != nil {
		t.Fatalf("failed to log: %v", err)
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		var readEv Event
		if err := json.Unmarshal(scanner.Bytes(), &readEv); err != nil {
			t.Fatal(err)
		}
		if readEv.Event != "command_executed" || readEv.Host != "10.0.0.1" {
			t.Errorf("unexpected logged event: %+v", readEv)
		}
	}
}
```

- [ ] **Step 3: Run Audit Tests**

Run: `cd interceptor && go test -v ./internal/audit/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add interceptor/internal/audit
git commit -m "feat(audit): implement dual-output JSON lines audit logger"
```

---

## Phase 5: CLI Shell & Commands Package

### Task 5.1: Create Cobra CLI Infrastructure

**Files:**
- Create: `interceptor/cmd/root.go`
- Create: `interceptor/cmd/serve.go`
- Create: `interceptor/cmd/exec.go`
- Create: `interceptor/cmd/policy.go`
- Create: `interceptor/cmd/approvals.go`
- Modify: `interceptor/main.go`

- [ ] **Step 1: Create Cobra Root Command**

Create `interceptor/cmd/root.go`:
```go
package cmd

import (
	"fmt"
	"os"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "luna",
	Short: "Luna: Zero-trust secure remote SSH agent and stdio MCP server",
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Add serve, exec, plan, policy and approvals Cobra Commands**

Create `interceptor/cmd/serve.go` (this will contain standard stdio server loop, similar to main.go):
```go
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/config"
	"github.com/ba0f3/lunacli/internal/policy"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/ba0f3/lunacli/internal/tools"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the stdio MCP server",
	Run: func(cmd *cobra.Command, args []string) {
		log.SetOutput(os.Stderr)
		log.Printf("starting zero-trust secure stdio server")

		cfgDir := config.ResolveConfigDir()
		_, err := policy.LoadPolicy(cfgDir)
		if err != nil {
			log.Fatalf("failed to load policy.yml (required): %v", err)
		}

		pool := ssh.NewPool()
		appCfg, err := approval.LoadConfigFromEnv()
		if err != nil {
			log.Fatalf("failed load approval config: %v", err)
		}

		store, err := approval.OpenSQLiteStore(appCfg.Store)
		if err != nil {
			log.Fatalf("SQLite error: %v", err)
		}
		defer store.Close()

		svc := approval.NewService(store, appCfg)
		gate := approval.NewGate(appCfg, svc, nil)

		s := server.NewMCPServer(
			"luna", "2.0.0",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		)

		tools.Register(s, pool, gate)
		if err := server.ServeStdio(s); err != nil {
			fmt.Fprintf(os.Stderr, "server runtime error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)
}
```

Create `interceptor/cmd/exec.go`:
```go
package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/policy"
	"github.com/ba0f3/lunacli/internal/ssh"
	"github.com/spf13/cobra"
)

var execCmd = &cobra.Command{
	Use:   "exec [host] [command]",
	Short: "Execute a remote command directly with policy check",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]
		command := args[1]

		cfgDir := config.ResolveConfigDir()
		pol, err := policy.LoadPolicy(cfgDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy required: %v\n", err)
			os.Exit(1)
		}

		eng := engine.NewEngine(pol)
		res := eng.Classify(command, host, nil)

		if res.Class == engine.Forbidden {
			fmt.Fprintf(os.Stderr, "Command Blocked: %s\n", res.Reason)
			os.Exit(1)
		}

		if res.Class == engine.Mutating {
			fmt.Fprintf(os.Stderr, "Mutating command requires approval: %s\n", res.Reason)
			os.Exit(1)
		}

		pool := ssh.NewPool()
		execRes, err := pool.Execute(host, command, 30*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SSH error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(execRes.Stdout)
		if execRes.Stderr != "" {
			fmt.Fprintln(os.Stderr, execRes.Stderr)
		}
		os.Exit(execRes.ExitCode)
	},
}

func init() {
	RootCmd.AddCommand(execCmd)
}
```

Create `interceptor/cmd/approvals.go`:
```go
package cmd

import (
	"fmt"
	"os"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/spf13/cobra"
)

var approvalsCmd = &cobra.Command{
	Use:   "approvals",
	Short: "Manage pending out-of-band approval requests",
}

var approvalsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all pending approvals",
	Run: func(cmd *cobra.Command, args []string) {
		appCfg, err := approval.LoadConfigFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		store, err := approval.OpenSQLiteStore(appCfg.Store)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer store.Close()
		svc := approval.NewService(store, appCfg)
		recs, err := svc.ListPending()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(recs) == 0 {
			fmt.Println("No pending approvals.")
			return
		}
		for _, r := range recs {
			fmt.Printf("[%s] Host: %s | Cmd: %s | Expires: %v\n", r.ID, r.Host, r.RedactedCommand, r.ExpiresAt)
		}
	},
}

var approvalsApproveCmd = &cobra.Command{
	Use:   "approve [id]",
	Short: "Approve a pending request",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]
		appCfg, err := approval.LoadConfigFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		store, err := approval.OpenSQLiteStore(appCfg.Store)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer store.Close()
		svc := approval.NewService(store, appCfg)
		if err := svc.Approve(id, "admin", "cli"); err != nil {
			fmt.Fprintf(os.Stderr, "failed to approve: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Approved.")
	},
}

func init() {
	approvalsCmd.AddCommand(approvalsListCmd)
	approvalsCmd.AddCommand(approvalsApproveCmd)
	RootCmd.AddCommand(approvalsCmd)
}
```

- [ ] **Step 3: Point main.go to Cobra Entrypoint**

Modify `interceptor/main.go`:
```go
package main

import (
	"log"
	"os"
	"github.com/ba0f3/lunacli/cmd"
)

func main() {
	log.SetOutput(os.Stderr)
	cmd.Execute()
}
```

- [ ] **Step 4: Build the Unified Dual-Mode Binary**

Run: `cd interceptor && go build -o ../bin/luna main.go`
Expected: compiles successfully to `bin/luna`.

- [ ] **Step 5: Verify CLI and Serve Command Runs**

Run: `./bin/luna --help`
Expected: displays help usage and subcommands.

- [ ] **Step 6: Commit**

```bash
git add interceptor/cmd interceptor/main.go
git commit -m "feat(cli): unify dual-mode CLI with Cobra framework"
```

---

## Verification Plan

### Automated Tests
- Command execution: `cd interceptor && go test -v ./...`
- Fuzzing classification seeds: `cd interceptor && go test -v ./internal/engine/...`

### Manual Verification
1. Create `./luna.d/policy.yml` with basic rules:
   ```yaml
   version: 1
   rules:
     - action: allow
       hosts: ["*"]
       commands:
         - binary: uptime
   ```
2. Run direct SSH CLI execution via new binary:
   `./bin/luna exec ubuntu@localhost uptime`
3. Launch stdio server using Cursor/Claude desktop client configuration pointing to `./bin/luna serve` and confirm connection.
