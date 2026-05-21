package approval

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestService_WaitForDecision_Approved(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	req, body, fp, err := BuildExecuteRemoteRequest("web1", "touch /tmp/x", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(50 * time.Millisecond)
		if err := svc.Approve(info.ID, "alice", "test"); err != nil {
			t.Errorf("Approve() error = %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st, err := svc.WaitForDecision(ctx, info.ID)
	<-done
	if err != nil {
		t.Fatalf("WaitForDecision() error = %v", err)
	}
	if st != StatusApproved {
		t.Fatalf("status = %q, want approved", st)
	}
}

func TestService_WaitForDecision_Denied(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	req, body, fp, err := BuildExecuteRemoteRequest("web1", "touch /tmp/x", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := svc.Deny(info.ID, "alice", "test"); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = svc.WaitForDecision(ctx, info.ID)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("WaitForDecision() error = %v, want ErrDenied", err)
	}
}

func TestService_WaitForDecision_ContextCancelled(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	req, body, fp, err := BuildExecuteRemoteRequest("web1", "touch /tmp/x", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = svc.WaitForDecision(ctx, info.ID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForDecision() error = %v, want context.Canceled", err)
	}
}
