package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostKeyAlgorithmsForKnownHost(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	const line = "mybox ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := HostKeyAlgorithmsForKnownHost(kh, "mybox", "22")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Fatalf("got %v want [ssh-ed25519]", got)
	}
	got2, err := HostKeyAlgorithmsForKnownHost(kh, "other", "22")
	if err != nil {
		t.Fatal(err)
	}
	if len(got2) != 0 {
		t.Fatalf("got %v want empty", got2)
	}
}
