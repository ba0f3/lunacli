package onboard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile_mergeSkipsExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	wrote, err := WriteFile(WriteMerge, p, []byte("new"), 0644)
	if err != nil || wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "old" {
		t.Fatalf("content = %q", b)
	}
}

func TestWriteFile_replaceOverwrites(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	_ = os.WriteFile(p, []byte("old"), 0644)
	wrote, err := WriteFile(WriteReplace, p, []byte("new"), 0644)
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
}

func TestInstallBundle_mergeSkipsExisting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ly, err := NewLayout(TargetUserWide)
	if err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(ly.PolicyDir, "policy.yml")
	if err := os.MkdirAll(ly.PolicyDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("custom"), 0644); err != nil {
		t.Fatal(err)
	}
	written, err := InstallBundle(WriteMerge, ly)
	if err != nil {
		t.Fatal(err)
	}
	if written["policy.yml"] {
		t.Fatal("expected policy.yml skipped")
	}
	b, _ := os.ReadFile(existing)
	if string(b) != "custom" {
		t.Fatalf("policy content = %q", b)
	}
}
