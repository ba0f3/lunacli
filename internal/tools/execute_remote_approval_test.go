package tools_test

import (
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/approval"
	"github.com/ba0f3/lunacli/internal/engine"
	"github.com/ba0f3/lunacli/internal/policy"
)

func testEngine() *engine.Engine {
	return engine.NewEngine(&policy.Policy{
		Version: 1,
		Rules: []policy.Rule{
			{
				Action: "allow",
				Hosts:  []string{"*"},
				Commands: []policy.CommandRule{
					{Binary: "uptime"},
					{Binary: "echo"},
				},
			},
			{
				Action: "approve",
				Hosts:  []string{"*"},
				Commands: []policy.CommandRule{
					{Binary: "touch"},
				},
			},
		},
	})
}

func executeRemoteGate(eng *engine.Engine, gate *approval.Gate, host, command string, timeoutSec float64, approvalID string) approval.GateResult {
	check := eng.Classify(command, host, nil)
	return gate.CheckExecuteRemote(check, host, command, timeoutSec, approvalID)
}

func TestExecuteRemoteGateSequence_Forbidden(t *testing.T) {
	eng := testEngine()
	gate := approval.NewGate(approval.Config{}, nil, nil)
	res := executeRemoteGate(eng, gate, "h", "rm -rf /", 30, "")
	if res.Kind != approval.GateBlocked {
		t.Fatalf("Kind = %v, want GateBlocked", res.Kind)
	}
	if !strings.HasPrefix(res.BlockedText, "BLOCKED:") {
		t.Fatalf("BlockedText = %q", res.BlockedText)
	}
}

func TestExecuteRemoteGateSequence_MutatingRequiresApproval(t *testing.T) {
	eng := testEngine()
	gate := approval.NewGate(approval.Config{}, nil, nil)
	cmd := "touch /tmp/foo"
	res := executeRemoteGate(eng, gate, "host", cmd, 30, "")
	if res.Kind != approval.GatePermissionRequired {
		t.Fatalf("Kind = %v, want GatePermissionRequired", res.Kind)
	}
	if !strings.HasPrefix(res.PermissionText, "PERMISSION_REQUIRED:") {
		t.Fatalf("PermissionText = %q", res.PermissionText)
	}
}

func TestExecuteRemoteGateSequence_ReadOnly(t *testing.T) {
	eng := testEngine()
	gate := approval.NewGate(approval.Config{}, nil, nil)
	res := executeRemoteGate(eng, gate, "host", "uptime", 30, "")
	if res.Kind != approval.GateExecute {
		t.Fatalf("Kind = %v, want GateExecute", res.Kind)
	}
}

func TestExecuteRemoteGateSequence_ApproveRetry(t *testing.T) {
	store := approval.NewMemoryStore()
	cfg := approval.Config{TTL: time.Minute}
	svc := approval.NewService(store, cfg)
	gate := approval.NewGate(cfg, svc, nil)
	eng := testEngine()

	host := "user@example.com"
	cmd := "touch /tmp/foo"
	timeout := float64(30)

	res := executeRemoteGate(eng, gate, host, cmd, timeout, "")
	if res.Kind != approval.GatePermissionRequired {
		t.Fatalf("Kind = %v, want GatePermissionRequired", res.Kind)
	}
	id := res.ApprovalID
	if id == "" {
		t.Fatal("expected ApprovalID")
	}
	if err := svc.Approve(id, "human", "test"); err != nil {
		t.Fatal(err)
	}
	res2 := executeRemoteGate(eng, gate, host, cmd, timeout, id)
	if res2.Kind != approval.GateExecute {
		t.Fatalf("Kind = %v, want GateExecute after approve", res2.Kind)
	}
}
