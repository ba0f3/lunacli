package approval

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

func TestGate_WaitTrustHostApproval(t *testing.T) {
	svc := NewService(NewMemoryStore(), Config{TTL: time.Minute})
	gate := NewGate(Config{TTL: time.Minute}, svc, nil)

	pubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gossh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	done := make(chan error, 1)
	go func() {
		done <- gate.WaitTrustHostApproval(context.Background(), "web1", "root@10.0.0.5", "root@10.0.0.5", dir, pub)
	}()

	var pendingID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending, err := svc.ListPending()
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 1 {
			pendingID = pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pendingID == "" {
		t.Fatal("expected pending host-trust approval")
	}
	if err := svc.Approve(pendingID, "human", "test"); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitTrustHostApproval() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitTrustHostApproval did not complete")
	}

	cfg, err := config.LoadHosts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 1 || cfg.Hosts[0].Alias != "web1" || cfg.Hosts[0].HostKey == "" {
		t.Fatalf("hosts.yml = %+v", cfg.Hosts)
	}
	trusted, err := cfg.Hosts[0].TrustedPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !config.PublicKeysEqual(trusted, pub) {
		t.Fatal("stored host_key mismatch")
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); err != nil {
		t.Fatalf("hosts.yml missing: %v", err)
	}
}

func TestBuildTrustHostRequest_FingerprintStable(t *testing.T) {
	req, body, fp, err := BuildTrustHostRequest("web1", "root@10.0.0.5", "root@10.0.0.5", "ssh-ed25519 AAA", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if req.Tool != trustHostToolName || fp == "" || len(body) == 0 {
		t.Fatalf("req=%+v fp=%q", req, fp)
	}
}

func TestFormatTelegramTrustHostMessage(t *testing.T) {
	text := formatTelegramTrustHostMessage(PendingInfo{ID: "12345678-1234-1234-1234-123456789012"}, ExecuteRemoteRequest{
		Tool:    trustHostToolName,
		Host:    "root@10.0.0.5",
		Command: "trust host web1 (abc)\nkey: ssh-ed25519 AAA",
	})
	if !strings.Contains(text, "TRUST HOST") || !strings.Contains(text, "10.0.0.5") {
		t.Fatalf("message = %q", text)
	}
}
