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
	t.Setenv("LUNA_APPROVAL_TTL", "")

	userDir := filepath.Join(home, ".config", "luna")
	if err := os.MkdirAll(userDir, 0755); err != nil {
		t.Fatal(err)
	}
	userJSON := `{"approval":{"ttl":"2m"}}`
	if err := os.WriteFile(filepath.Join(userDir, "config.json"), []byte(userJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cwdConfigDir := filepath.Join(project, ".config", "luna")
	if err := os.MkdirAll(cwdConfigDir, 0755); err != nil {
		t.Fatal(err)
	}
	cwdJSON := `{"approval":{"ttl":"4m"}}`
	if err := os.WriteFile(filepath.Join(cwdConfigDir, "config.json"), []byte(cwdJSON), 0644); err != nil {
		t.Fatal(err)
	}

	localJSON := `{"approval":{"ttl":"3m"},"config_dir":"./luna.d"}`
	if err := os.WriteFile(filepath.Join(project, localConfigFile), []byte(localJSON), 0644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "3m0s" {
		t.Errorf("ApprovalTTL = %v, %v", ttl, err)
	}
	if got := s.ConfigDir(); got != "./luna.d" {
		t.Errorf("ConfigDir = %q, want ./luna.d", got)
	}

	t.Setenv("LUNA_APPROVAL_TTL", "1m")
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "1m0s" {
		t.Errorf("ApprovalTTL with env = %v, %v", ttl, err)
	}
}

func TestLoadSettings_CwdConfigOverridesUser(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_CONFIG_DIR", "")
	t.Setenv("LUNA_APPROVAL_TTL", "")

	userDir := filepath.Join(home, ".config", "luna")
	if err := os.MkdirAll(userDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "config.json"),
		[]byte(`{"approval":{"ttl":"2m"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	cwdConfigDir := filepath.Join(project, ".config", "luna")
	if err := os.MkdirAll(cwdConfigDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwdConfigDir, "config.json"),
		[]byte(`{"approval":{"ttl":"4m"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
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
		[]byte(`{"approval":{"ttl":"3m"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, dotEnvFile),
		[]byte("LUNA_APPROVAL_TTL=2m\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("LUNA_APPROVAL_TTL") })

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "2m0s" {
		t.Errorf("ApprovalTTL = %v, %v", ttl, err)
	}
}

func TestLoadSettings_DotEnvDoesNotOverrideProcessEnv(t *testing.T) {
	project := t.TempDir()
	t.Setenv("LUNA_APPROVAL_TTL", "1m")

	if err := os.WriteFile(filepath.Join(project, dotEnvFile),
		[]byte("LUNA_APPROVAL_TTL=2m\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("LUNA_APPROVAL_TTL") })

	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "1m0s" {
		t.Errorf("ApprovalTTL = %v, %v", ttl, err)
	}
}

func TestLoadSettings_MissingFilesOK(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_APPROVAL_TTL", "")
	t.Chdir(project)

	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if ttl, err := s.ApprovalTTL(); err != nil || ttl.String() != "5m0s" {
		t.Errorf("ApprovalTTL default = %v, %v", ttl, err)
	}
}
