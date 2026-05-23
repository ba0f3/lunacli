package onboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/lunacli/internal/config"
)

func TestLayout_userWide(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ly, err := NewLayout(TargetUserWide)
	if err != nil {
		t.Fatal(err)
	}
	wantConfig := filepath.Join(home, ".config", "luna", "luna.config.json")
	if ly.ConfigJSON != wantConfig {
		t.Errorf("ConfigJSON = %q, want %q", ly.ConfigJSON, wantConfig)
	}
	if ly.ConfigDirRel != "luna.d" {
		t.Errorf("ConfigDirRel = %q", ly.ConfigDirRel)
	}
	if ly.PolicyDir != filepath.Join(home, ".config", "luna", "luna.d") {
		t.Errorf("PolicyDir = %q", ly.PolicyDir)
	}
}

func TestLayout_projectLocal(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	ly, err := NewLayout(TargetProjectLocal)
	if err != nil {
		t.Fatal(err)
	}
	if ly.ConfigJSON != filepath.Join(dir, "luna.config.json") {
		t.Errorf("ConfigJSON = %q", ly.ConfigJSON)
	}
	if ly.ConfigDirRel != "./luna.d" {
		t.Errorf("ConfigDirRel = %q", ly.ConfigDirRel)
	}
	if ly.PolicyDir != filepath.Join(dir, "luna.d") {
		t.Errorf("PolicyDir = %q", ly.PolicyDir)
	}
}

func TestLayout_serveFindsPolicy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LUNA_CONFIG_DIR", "")
	ly, err := NewLayout(TargetUserWide)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtractBundle(embeddedBundle, ly.PolicyDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ly.ConfigJSON), 0755); err != nil {
		t.Fatal(err)
	}
	fs := config.FileSettings{ConfigDir: ly.ConfigDirRel}
	data, err := json.Marshal(fs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ly.ConfigJSON, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	s, err := config.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	got := s.ConfigDir()
	if got != ly.PolicyDir {
		t.Errorf("ConfigDir = %q, want %q", got, ly.PolicyDir)
	}
}
