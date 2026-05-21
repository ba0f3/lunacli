package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSettings_FilePrecedenceAndEnvOverride(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
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

	cwdConfigDir := filepath.Join(project, ".config", "luna")
	if err := os.MkdirAll(cwdConfigDir, 0755); err != nil {
		t.Fatal(err)
	}
	cwdJSON := `{"approval":{"store":"cwd.db","ttl":"4m"}}`
	if err := os.WriteFile(filepath.Join(cwdConfigDir, "config.json"), []byte(cwdJSON), 0644); err != nil {
		t.Fatal(err)
	}

	localJSON := `{"approval":{"store":"local.db","ttl":"3m"},"config_dir":"./luna.d"}`
	if err := os.WriteFile(filepath.Join(project, localConfigFile), []byte(localJSON), 0644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(project)

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

func TestLoadSettings_CwdConfigOverridesUser(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_CONFIG_DIR", "")
	t.Setenv("LUNA_APPROVAL_STORE", "")
	t.Setenv("LUNA_APPROVAL_TTL", "")

	userDir := filepath.Join(home, ".config", "luna")
	if err := os.MkdirAll(userDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "config.json"),
		[]byte(`{"approval":{"store":"user.db","ttl":"2m"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	cwdConfigDir := filepath.Join(project, ".config", "luna")
	if err := os.MkdirAll(cwdConfigDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwdConfigDir, "config.json"),
		[]byte(`{"approval":{"store":"cwd.db","ttl":"4m"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ApprovalStore(); got != "cwd.db" {
		t.Errorf("ApprovalStore = %q, want cwd.db", got)
	}
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "4m0s" {
		t.Errorf("ApprovalTTL = %v, %v", ttl, err)
	}
}

func TestLoadSettings_CwdDotConfigJSON(t *testing.T) {
	project := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	dotConfigDir := filepath.Join(project, ".config")
	if err := os.MkdirAll(dotConfigDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dotConfigDir, "luna.config.json"),
		[]byte(`{"config_dir":".config/luna.d"}`), 0644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ConfigDir(); got != ".config/luna.d" {
		t.Errorf("ConfigDir = %q, want .config/luna.d", got)
	}
}

func TestLoadSettings_DotEnvOverridesJSON(t *testing.T) {
	project := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := os.WriteFile(filepath.Join(project, localConfigFile),
		[]byte(`{"approval":{"store":"local.db"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, dotEnvFile),
		[]byte("LUNA_APPROVAL_STORE=dotenv.db\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("LUNA_APPROVAL_STORE") })

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ApprovalStore(); got != "dotenv.db" {
		t.Errorf("ApprovalStore = %q, want dotenv.db", got)
	}
}

func TestLoadSettings_DotEnvDoesNotOverrideProcessEnv(t *testing.T) {
	project := t.TempDir()
	t.Setenv("LUNA_APPROVAL_STORE", "shell.db")

	if err := os.WriteFile(filepath.Join(project, dotEnvFile),
		[]byte("LUNA_APPROVAL_STORE=dotenv.db\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("LUNA_APPROVAL_STORE") })

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ApprovalStore(); got != "shell.db" {
		t.Errorf("ApprovalStore = %q, want shell.db", got)
	}
}

func TestLoadSettings_MissingFilesOK(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_APPROVAL_STORE", "")
	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ApprovalStore(); got != "approvals.db" {
		t.Errorf("ApprovalStore default = %q", got)
	}
}
