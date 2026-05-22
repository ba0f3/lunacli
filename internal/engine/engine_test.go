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
