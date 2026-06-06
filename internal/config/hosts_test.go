package config

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

func TestLoadHosts(t *testing.T) {
	tmp := t.TempDir()

	content := `
version: 1
hosts:
  - alias: test-prod
    host: root@10.0.0.1
    tags: [prod, web]
    description: "test host"
`
	if err := os.WriteFile(filepath.Join(tmp, "hosts.yml"), []byte(content), 0o644); err != nil {
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

func TestUpsertHostEntry(t *testing.T) {
	tmp := t.TempDir()

	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gossh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	keyLine := FormatHostKeyLine(pub)

	entry := HostEntry{
		Alias:       "web1",
		Host:        "root@10.0.0.5",
		HostKey:     keyLine,
		Description: "test",
	}
	if err := UpsertHostEntry(tmp, entry); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadHosts(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 {
		t.Fatalf("hosts = %+v", cfg.Hosts)
	}
	got, err := cfg.Hosts[0].TrustedPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !PublicKeysEqual(got, pub) {
		t.Fatal("trusted key mismatch")
	}

	entry.Description = "updated"
	if err := UpsertHostEntry(tmp, entry); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadHosts(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 || cfg.Hosts[0].Description != "updated" {
		t.Fatalf("upsert update failed: %+v", cfg.Hosts)
	}
}

func TestMatchHostEntry(t *testing.T) {
	cfg := &HostsConfig{Hosts: []HostEntry{
		{Alias: "r2d-infra", Host: "root@100.64.0.16", HostKey: "ssh-ed25519 AAA"},
	}}
	if got := MatchHostEntry(cfg, "100.64.0.16"); got == nil || got.Alias != "r2d-infra" {
		t.Fatalf("MatchHostEntry() = %+v", got)
	}
	if got := MatchHostEntry(cfg, "missing"); got != nil {
		t.Fatalf("MatchHostEntry() = %+v, want nil", got)
	}
}

func TestPromptAddHostEntryDeclined(t *testing.T) {
	tmp := t.TempDir()

	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gossh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	added, err := PromptAddHostEntry(strings.NewReader("n\n"), discardWriter{}, tmp, "web1", "root@10.0.0.5", pub)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("expected declined prompt")
	}
	cfg, err := LoadHosts(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 0 {
		t.Fatalf("hosts = %+v", cfg.Hosts)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
