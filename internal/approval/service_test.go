package approval

import (
	"errors"
	"testing"
	"time"
)

func TestService_ApproveThenConsumeOnce(t *testing.T) {
	base := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	clock := base

	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Hour})
	svc.now = func() time.Time { return clock }

	req, body, fp, err := BuildExecuteRemoteRequest("web1", "echo hello", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}

	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if info.ID == "" {
		t.Fatal("CreatePending() empty ID")
	}
	if info.Fingerprint != fp {
		t.Fatalf("Fingerprint = %q, want %q", info.Fingerprint, fp)
	}
	if info.FingerprintPrefix != FingerprintPrefix(fp) {
		t.Fatalf("FingerprintPrefix = %q", info.FingerprintPrefix)
	}

	if err := svc.Approve(info.ID, "alice", "cli"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := svc.VerifyAndConsume(info.ID, req, body, fp); err != nil {
		t.Fatalf("VerifyAndConsume first error = %v", err)
	}
	if err := svc.VerifyAndConsume(info.ID, req, body, fp); !errors.Is(err, ErrConsumed) {
		t.Fatalf("VerifyAndConsume second error = %v, want ErrConsumed", err)
	}
}

func TestService_RejectMismatchedCommand(t *testing.T) {
	base := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)

	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Hour})
	svc.now = func() time.Time { return base }

	req, body, fp, err := BuildExecuteRemoteRequest("web1", "echo hello", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}

	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := svc.Approve(info.ID, "alice", "cli"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	req2, body2, fp2, err := BuildExecuteRemoteRequest("web1", "echo goodbye", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}

	if err := svc.VerifyAndConsume(info.ID, req2, body2, fp2); !errors.Is(err, ErrMismatch) {
		t.Fatalf("VerifyAndConsume mismatched error = %v, want ErrMismatch", err)
	}
}
