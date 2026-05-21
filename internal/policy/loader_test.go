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
