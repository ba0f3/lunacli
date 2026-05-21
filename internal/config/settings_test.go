package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSettings_FilePrecedenceAndEnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_CONFIG_DIR", "")
	t.Setenv("LUNA_APPROVAL_STORE", "")
	t.Setenv("LUNA_APPROVAL_TTL", "")
	t.Setenv("LUNA_APPROVAL_PROVIDER", "")

	userDir := filepath.Join(home, ".config", "luna")
	if err := os.MkdirAll(userDir, 0755); err != nil {
		t.Fatal(err)
	}
	userJSON := `{"approval":{"store":"user.db","ttl":"2m","provider":"fake"},"cli":{"approver_users":["111"]}}`
	if err := os.WriteFile(filepath.Join(userDir, "config.json"), []byte(userJSON), 0644); err != nil {
		t.Fatal(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	localJSON := `{"approval":{"store":"local.db","ttl":"3m"},"config_dir":"./luna.d"}`
	if err := os.WriteFile(filepath.Join(wd, localConfigFile), []byte(localJSON), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(wd, localConfigFile)) })

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ApprovalStore(); got != "local.db" {
		t.Errorf("ApprovalStore = %q, want local.db", got)
	}
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "3m0s" {
		t.Errorf("ApprovalTTL = %v, %v", ttl, err)
	}
	if got := s.ConfigDir(); got != "./luna.d" {
		t.Errorf("ConfigDir = %q, want ./luna.d", got)
	}
	if got := s.CLIApproverUsers(); got != "111" {
		t.Errorf("CLIApproverUsers = %q, want 111 from user file", got)
	}

	t.Setenv("LUNA_APPROVAL_STORE", "env.db")
	if got := s.ApprovalStore(); got != "env.db" {
		t.Errorf("ApprovalStore with env = %q, want env.db", got)
	}
}

func TestLoadSettings_MissingFilesOK(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(wd, localConfigFile)) })
	_ = os.Remove(filepath.Join(wd, localConfigFile))

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ApprovalStore(); got != "approvals.db" {
		t.Errorf("ApprovalStore default = %q", got)
	}
}
