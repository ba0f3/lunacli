package approval

import (
	"testing"
	"time"
)

func TestLoadConfigFromEnv_DefaultTTL(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_TTL", "")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.TTL != 5*time.Minute {
		t.Errorf("TTL: got %v, want 5m", cfg.TTL)
	}
}

func TestLoadConfigFromEnv_CustomTTL(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_TTL", "2m")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.TTL != 2*time.Minute {
		t.Errorf("TTL: got %v, want 2m", cfg.TTL)
	}
}

func TestLoadConfigFromEnv_InvalidTTL(t *testing.T) {
	t.Setenv("LUNA_APPROVAL_TTL", "not-a-duration")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error for invalid TTL")
	}
}
