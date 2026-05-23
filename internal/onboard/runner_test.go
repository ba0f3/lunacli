package onboard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_nonInteractiveFails(t *testing.T) {
	fi, err := os.Stdin.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		t.Skip("stdin is a terminal; cannot test non-TTY path")
	}
	err = Run(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error without TTY")
	}
	if !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallBundle_writesHostsSkeleton(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ly, err := NewLayout(TargetUserWide)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallBundle(WriteReplace, ly); err != nil {
		t.Fatal(err)
	}
	hostsPath := filepath.Join(ly.PolicyDir, "hosts.yml")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "example-host") {
		t.Fatalf("hosts.yml = %s", data)
	}
}
