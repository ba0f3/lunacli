package approval

import (
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/engine"
)

func TestGate_SessionGrant_ReusesSameHostCommand(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Minute})
	gate := NewGate(Config{}, svc, nil)

	host := "root@100.64.0.86:22"
	cmd := "nginx -v 2>&1"
	timeout := 30.0

	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("first Kind = %v, want permission required", res.Kind)
	}
	if err := svc.Approve(res.ApprovalID, "human", "test"); err != nil {
		t.Fatal(err)
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
		t.Fatal("expected SessionGrant on reused call")
	}
}

func TestGate_SessionGrant_ReusesCommandOnOtherHost(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Minute})
	gate := NewGate(Config{}, svc, nil)

	cmd := "nginx -v 2>&1"
	timeout := 30.0

	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, "root@100.64.0.86:22", cmd, timeout, "")
	if err := svc.Approve(res.ApprovalID, "human", "test"); err != nil {
		t.Fatal(err)
	}
	res2 := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, "root@100.64.0.86:22", cmd, timeout, res.ApprovalID)
	if res2.Kind != GateExecute {
		t.Fatalf("consume Kind = %v, want execute", res2.Kind)
	}
	res3 := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, "root@100.64.0.10:22", cmd, timeout, "")
	if res3.Kind != GateExecute {
		t.Fatalf("other host Kind = %v, want execute via command grant", res2.Kind)
	}
	if !res3.SessionGrant {
		t.Fatal("expected SessionGrant on fleet reuse")
	}
}

func TestGate_SessionGrant_ExpiresWithTTL(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	svc := NewService(store, Config{TTL: time.Minute})
	svc.now = func() time.Time { return now }
	gate := NewGate(Config{}, svc, nil)

	host := "root@100.64.0.86:22"
	cmd := "nginx -v 2>&1"
	timeout := 30.0

	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, "")
	if err := svc.Approve(res.ApprovalID, "human", "test"); err != nil {
		t.Fatal(err)
	}
	gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, res.ApprovalID)

	now = now.Add(2 * time.Minute)
	res2 := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, cmd, timeout, "")
	if res2.Kind != GatePermissionRequired {
		t.Fatalf("after TTL Kind = %v, want permission required", res2.Kind)
	}
}

func TestGate_SessionGrant_DifferentCommandRequiresApproval(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Minute})
	gate := NewGate(Config{}, svc, nil)

	host := "root@100.64.0.86:22"
	timeout := 30.0

	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, "nginx -v 2>&1", timeout, "")
	if err := svc.Approve(res.ApprovalID, "human", "test"); err != nil {
		t.Fatal(err)
	}
	gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, "nginx -v 2>&1", timeout, res.ApprovalID)

	res2 := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, host, "which nginx", timeout, "")
	if res2.Kind != GatePermissionRequired {
		t.Fatalf("different command Kind = %v, want permission required", res2.Kind)
	}
}
