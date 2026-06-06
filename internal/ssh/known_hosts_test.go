package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

func TestHostKeyAlgorithmsForKnownHost_hashed(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	const host = "hostname"
	hashed := knownhosts.HashHostname(host)
	line := hashed + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := HostKeyAlgorithmsForKnownHost(kh, host, "22")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ssh-ed25519" {
		t.Fatalf("got %v want [ssh-ed25519]", got)
	}

	ok, err := HasKnownHostEntry(kh, host, "22")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("HasKnownHostEntry() = false, want true")
	}
}

func TestParseKnownHosts_hashedViaSSHConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const realHost = "server.example"
	hashed := knownhosts.HashHostname(realHost)
	khLine := hashed + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(khLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "Host myserver\n  HostName server.example\n  Port 22\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ParseKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(got, "myserver") {
		t.Fatalf("ParseKnownHosts() = %v, want SSH alias myserver", got)
	}
}

func TestResolveSSHConfigHost(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "Host alias\n  HostName 10.0.0.5\n  Port 2222\n  HostKeyAlias stable-host-key\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	host, port := resolveSSHConfigHost("alias", "22")
	if host != "10.0.0.5" || port != "2222" {
		t.Fatalf("resolveSSHConfigHost() = %q:%q, want 10.0.0.5:2222", host, port)
	}
	if got := resolveSSHConfigHostKeyAlias("alias", host); got != "stable-host-key" {
		t.Fatalf("resolveSSHConfigHostKeyAlias() = %q, want stable-host-key", got)
	}
	host, port = resolveSSHConfigHost("alias", "8022")
	if host != "10.0.0.5" || port != "8022" {
		t.Fatalf("explicit port: got %q:%q, want 10.0.0.5:8022", host, port)
	}
}

func TestCanonicalTarget_UsesResolvedSSHConfigDestination(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "Host alias\n  HostName 127.0.0.1\n  Port 2222\n  User alice\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := canonicalTarget("alias")
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "alice" || got.Host != "127.0.0.1" || got.Port != "2222" || got.Raw != "alice@127.0.0.1:2222" || got.Alias != "alias" {
		t.Fatalf("canonicalTarget() = %+v", got)
	}
}

func TestIsConcreteSSHHostPattern(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"mybox", true},
		{"server.example", true},
		{"*", false},
		{"*.example.com", false},
		{"host?", false},
	} {
		if got := isConcreteSSHHostPattern(tc.in); got != tc.want {
			t.Errorf("isConcreteSSHHostPattern(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParsePlainKnownHostsLine(t *testing.T) {
	got := parsePlainKnownHostsLine("|1|abc|def ssh-ed25519 AAA")
	if len(got) != 0 {
		t.Fatalf("hashed line: got %v want empty", got)
	}
	got = parsePlainKnownHostsLine("host1,host2 ssh-ed25519 AAA")
	if len(got) != 2 || !containsString(got, "host1") || !containsString(got, "host2") {
		t.Fatalf("plain line: got %v", got)
	}
	bracket := parsePlainKnownHostsLine("[192.168.1.50]:2222 ssh-ed25519 AAA")
	if len(bracket) != 1 || bracket[0] != "192.168.1.50" {
		t.Fatalf("bracket line: got %v", bracket)
	}
}

func TestParseKnownHosts_hashedUnderAliasLabel(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const alias = "r2d-infra"
	const hostName = "10.9.5.15"
	hashed := knownhosts.HashHostname(alias)
	khLine := hashed + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(khLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "Host " + alias + "\n  HostName " + hostName + "\n  Port 22\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ok, err := HasKnownHostEntryForTarget("", filepath.Join(sshDir, "known_hosts"), alias, hostName, "22")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("HasKnownHostEntryForTarget() = false, want true")
	}

	got, err := ParseKnownHosts()
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(got, alias) {
		t.Fatalf("ParseKnownHosts() = %v, want alias %q", got, alias)
	}
	if !containsString(got, hostName) {
		t.Fatalf("ParseKnownHosts() = %v, want resolved host %q", got, hostName)
	}
}

func TestHasKnownHostEntryForTarget_dialByResolvedIPWithAliasHash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const alias = "myalias"
	hashed := knownhosts.HashHostname(alias)
	khLine := hashed + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(khLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "Host " + alias + "\n  HostName localhost\n  Port 22\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	khPath := filepath.Join(sshDir, "known_hosts")
	ok, err := HasKnownHostEntryForTarget("", khPath, "127.0.0.1", "127.0.0.1", "22")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("dial-by-resolved IP should match alias-hashed known_hosts entry")
	}
}

func TestHasKnownHostEntryForTarget_dialByIPWithAliasHash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const alias = "r2d-infra"
	const hostName = "10.9.5.15"
	hashed := knownhosts.HashHostname(alias)
	khLine := hashed + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(khLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "Host " + alias + "\n  HostName " + hostName + "\n  Port 22\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	khPath := filepath.Join(sshDir, "known_hosts")
	ok, err := HasKnownHostEntryForTarget("", khPath, hostName, hostName, "22")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("dial-by-IP should match alias-hashed known_hosts entry")
	}
}

func TestParseKnownHosts_hashedHostKeyAlias(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	const alias = "mybox"
	const hostName = "10.0.0.5"
	const keyAlias = "stable-host-key"
	hashed := knownhosts.HashHostname(keyAlias)
	khLine := hashed + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIANWLcHyZmh3BN1W11kQt+oPgmyLiDLmYD7FV8NoulPz"
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(khLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "Host " + alias + "\n  HostName " + hostName + "\n  HostKeyAlias " + keyAlias + "\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	ok, err := HasKnownHostEntryForTarget("", filepath.Join(sshDir, "known_hosts"), alias, hostName, "22")
	if err != nil || !ok {
		t.Fatalf("HasKnownHostEntryForTarget() = %v, %v; want true", ok, err)
	}
}
