package tools

import "testing"

func TestRedactSecretLikeArgs(t *testing.T) {
	input := "postgres --user app --password supersecret --token=abc123 --safe value AWS_SECRET_ACCESS_KEY=secret"
	got := redactSecretLikeArgs(input)
	want := "postgres --user app --password [REDACTED] --token=[REDACTED] --safe value AWS_SECRET_ACCESS_KEY=[REDACTED]"
	if got != want {
		t.Fatalf("redactSecretLikeArgs() = %q, want %q", got, want)
	}
}

func TestParseDPKGPackages(t *testing.T) {
	out := "nginx\t1.24.0-1\tamd64\nopenssl\t3.0.13-1\tamd64\n"
	got := parseDPKGPackages(out)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Manager != "dpkg" || got[0].Name != "nginx" || got[0].Version != "1.24.0-1" || got[0].Arch != "amd64" {
		t.Fatalf("unexpected first package: %+v", got[0])
	}
}

func TestParseRPMPackages(t *testing.T) {
	out := "openssl\t1:3.2.2-1.el9\tx86_64\n"
	got := parseRPMPackages(out)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Manager != "rpm" || got[0].Name != "openssl" || got[0].Version != "1:3.2.2-1.el9" || got[0].Arch != "x86_64" {
		t.Fatalf("unexpected package: %+v", got[0])
	}
}

func TestParseAPKPackages(t *testing.T) {
	out := "musl-1.2.5-r0 description:\nnginx-1.24.0-r1 description:\n"
	got := parseAPKPackages(out)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[1].Manager != "apk" || got[1].Name != "nginx" || got[1].Version != "1.24.0-r1" {
		t.Fatalf("unexpected package: %+v", got[1])
	}
}

func TestParseSystemdServices(t *testing.T) {
	out := "sshd.service  loaded  active  running  OpenSSH server daemon\n"
	got := parseSystemdServices(out)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Name != "sshd.service" || got[0].ActiveState != "active" || got[0].SubState != "running" {
		t.Fatalf("unexpected service: %+v", got[0])
	}
}

func TestParseProcessesRedactsCommand(t *testing.T) {
	out := "root 123 0.0 1.2 /usr/bin/app --api-key secret\n"
	got := parsePSProcesses(out)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Command != "/usr/bin/app --api-key [REDACTED]" {
		t.Fatalf("command = %q", got[0].Command)
	}
}

func TestParseSSPorts(t *testing.T) {
	out := "tcp\tLISTEN\t0\t4096\t0.0.0.0:22\t0.0.0.0:*\tusers:((\"sshd\",pid=100,fd=3))\n"
	got := parseSSPorts(out)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Protocol != "tcp" || got[0].State != "LISTEN" || got[0].Local != "0.0.0.0:22" || got[0].Process == "" {
		t.Fatalf("unexpected port: %+v", got[0])
	}
}

func TestParseWazuhClientKeys(t *testing.T) {
	out := "001 server-a any abcdef\n"
	got := parseWazuhClientKeys(out)
	if got.AgentID != "001" || got.AgentName != "server-a" {
		t.Fatalf("unexpected wazuh hint: %+v", got)
	}
}
