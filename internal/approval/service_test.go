package approval

import (
	"errors"
	"sync"
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

func TestService_RejectsCommandDifferingOnlyByRedactedSecret(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Hour})

	req, body, fp, err := BuildExecuteRemoteRequest("web1", "curl -H 'Authorization: Bearer first' https://example.test", 30)
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Approve(info.ID, "alice", "cli"); err != nil {
		t.Fatal(err)
	}

	changed, changedBody, changedFP, err := BuildExecuteRemoteRequest("web1", "curl -H 'Authorization: Bearer second' https://example.test", 30)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyAndConsume(info.ID, changed, changedBody, changedFP); !errors.Is(err, ErrMismatch) {
		t.Fatalf("VerifyAndConsume() error = %v, want ErrMismatch", err)
	}
}

func TestService_ConcurrentConsumeAllowsExactlyOne(t *testing.T) {
	store := NewMemoryStore()
	svc := NewService(store, Config{TTL: time.Hour})
	req, body, fp, err := BuildExecuteRemoteRequest("web1", "touch /tmp/x", 30)
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.CreatePending(req.Tool, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Approve(info.ID, "alice", "cli"); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- svc.VerifyAndConsume(info.ID, req, body, fp)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var success, consumed int
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrConsumed):
			consumed++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 || consumed != 1 {
		t.Fatalf("success=%d consumed=%d, want 1 each", success, consumed)
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
