package approval

import (
	"os"
	"testing"
	"time"
)

func isolatedConfigEnv(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_CONFIG_DIR", "")
	t.Setenv("LUNA_APPROVAL_TTL", "")
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigFromEnv_DefaultTTL(t *testing.T) {
	isolatedConfigEnv(t)

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv() error = %v", err)
	}
	if cfg.TTL != 5*time.Minute {
		t.Errorf("TTL: got %v, want 5m", cfg.TTL)
	}
}

func TestLoadConfigFromEnv_CustomTTL(t *testing.T) {
	isolatedConfigEnv(t)
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
	isolatedConfigEnv(t)
	t.Setenv("LUNA_APPROVAL_TTL", "not-a-duration")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error for invalid TTL")
	}
}
