package approval

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStore_InsertAndGetPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC()
	rec := Record{
		ID:               "apr-test-1",
		Tool:             "execute_remote",
		Host:             "web1",
		RedactedCommand:  "systemctl restart nginx",
		NormalizedBody:   []byte(`{"tool":"execute_remote","host":"web1","command":"systemctl restart nginx"}`),
		Classification:   "mutating",
		Reason:           "mutating command",
		Fingerprint:      "abc",
		Status:           StatusPending,
		CreatedAt:        now,
		ExpiresAt:        now.Add(5 * time.Minute),
		RedactionVersion: RedactionVersion,
	}
	if err := store.InsertPending(rec); err != nil {
		t.Fatalf("InsertPending() error = %v", err)
	}
	got, err := store.Get("apr-test-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Status != StatusPending {
		t.Fatalf("Status = %q, want pending", got.Status)
	}
}
