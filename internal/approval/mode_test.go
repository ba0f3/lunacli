package approval

import (
	"testing"
	"time"
)

func TestLoadConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_STORE", "")
	t.Setenv("LUNA_APPROVAL_TTL", "")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Store != "approvals.db" {
		t.Errorf("Store: got %q, want approvals.db", cfg.Store)
	}
	if cfg.TTL != 5*time.Minute {
		t.Errorf("TTL: got %v, want %v", cfg.TTL, 5*time.Minute)
	}
}

func TestLoadConfigFromEnv_CustomStoreAndTTL(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_STORE", "/tmp/approval-store")
	t.Setenv("LUNA_APPROVAL_TTL", "2m")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Store != "/tmp/approval-store" {
		t.Errorf("Store: got %q, want /tmp/approval-store", cfg.Store)
	}
	if cfg.TTL != 2*time.Minute {
		t.Errorf("TTL: got %v, want %v", cfg.TTL, 2*time.Minute)
	}
}

func TestLoadConfigFromEnv_InvalidTTL(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_TTL", "not-a-duration")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
