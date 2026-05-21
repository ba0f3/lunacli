package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFakeProvider_ApproveViaCallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})

	provider := NewFakeProvider(svc, "fake")
	req, body, fp, err := BuildExecuteRemoteRequest("web1", "touch /tmp/luna-approval-test", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	pending, err := svc.CreatePending("execute_remote", req, body, fp, "mutating", "touch")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := provider.Notify(pending, req); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if err := provider.Approve(pending.ID, "test-human"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := svc.VerifyAndConsume(pending.ID, req, body, fp); err != nil {
		t.Fatalf("VerifyAndConsume() error = %v", err)
	}
}
