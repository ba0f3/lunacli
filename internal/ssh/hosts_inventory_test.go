package ssh

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

func TestVerifyHostKeyFromInventory(t *testing.T) {
	tmp := t.TempDir()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := gossh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	otherPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := gossh.NewPublicKey(otherPubKey)
	if err != nil {
		t.Fatal(err)
	}

	entry := config.HostEntry{
		Alias:   "web1",
		Host:    "root@10.0.0.5",
		HostKey: config.FormatHostKeyLine(serverPub),
	}
	if err := config.UpsertHostEntry(tmp, entry); err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyHostKeyFromInventory(tmp, "web1", "10.0.0.5", "22", serverPub)
	if err != nil || !ok {
		t.Fatalf("VerifyHostKeyFromInventory() = %v, %v; want true", ok, err)
	}

	ok, err = VerifyHostKeyFromInventory(tmp, "web1", "10.0.0.5", "22", otherPub)
	if err != nil || ok {
		t.Fatalf("VerifyHostKeyFromInventory(other) = %v, %v; want false", ok, err)
	}

	ok, err = HasKnownHostEntryForTarget(tmp, filepath.Join(tmp, "missing-known_hosts"), "web1", "10.0.0.5", "22")
	if err != nil || !ok {
		t.Fatalf("HasKnownHostEntryForTarget(inventory) = %v, %v; want true", ok, err)
	}

	hosts, err := parseTrustedHosts(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(hosts, "web1") {
		t.Fatalf("parseTrustedHosts() = %v, want web1", hosts)
	}
}
