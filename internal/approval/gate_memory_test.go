package approval

import (
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/engine"
)

func TestGate_NilService_MutatingRequiresApproval(t *testing.T) {
	gate := NewGate(Config{}, nil, nil)
	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, "host", "cmd", 30, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("Kind = %v, want GatePermissionRequired", res.Kind)
	}
}

func TestGate_MemoryStore_MutatingApproveAndExecute(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Minute})
	gate := NewGate(Config{}, svc, nil)

	host := "web1"
	cmd := "touch /tmp/luna-gate-mem"
	timeout := 30.0

	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("first Kind = %v, want permission required", res.Kind)
	}
	if res.ApprovalID == "" {
		t.Fatal("expected approval id")
	}

	if err := svc.Approve(res.ApprovalID, "human", "test"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	res2 := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, res.ApprovalID)
	if res2.Kind != GateExecute {
		t.Fatalf("second Kind = %v, want execute", res2.Kind)
	}

	res3 := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, "")
	if res3.Kind != GateExecute {
		t.Fatalf("third Kind = %v, want execute via session grant", res3.Kind)
	}
	if !res3.SessionGrant {
		t.Fatal("expected SessionGrant after consume")
	}
}
