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
	defer func() { _ = os.RemoveAll(tmp) }()

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
