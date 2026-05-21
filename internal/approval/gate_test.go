package approval

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/engine"
)

func TestGate_MutatingRequiresApproval(t *testing.T) {
	gate := NewGate(Config{}, nil, nil)
	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, "h", "touch /tmp/x", 30, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("Kind = %v, want permission required without approval_id", res.Kind)
	}
}

func TestGate_MutatingWithApprovalID(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	providers := NewProviderSet(NewFakeProvider(svc, "fake"))
	gate := NewGate(Config{}, svc, providers)

	res := gate.CheckExecuteRemote(engine.Result{Class: engine.Mutating, Reason: "mutating"}, "h", "touch /tmp/x", 30, "")
	if res.Kind != GatePermissionRequired {
		t.Fatalf("Kind = %v, want permission required", res.Kind)
	}
	if res.ApprovalID == "" {
		t.Fatal("expected approval id in pending response")
	}
}
