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
