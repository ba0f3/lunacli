package onboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractBundle(t *testing.T) {
	tests := []struct {
		name          string
		setupBundle   func(t *testing.T) []byte
		expectError   bool
		errorContains string
		checkFiles    []string
	}{
		{
			name: "safeAndWritesFiles",
			setupBundle: func(t *testing.T) []byte {
				return embeddedBundle
			},
			expectError: false,
			checkFiles:  []string{"policy.yml", "hosts.yml"},
		},
		{
			name: "rejectsTraversal",
			setupBundle: func(t *testing.T) []byte {
				bad, err := tarGzBytes([]tarEntry{{Name: "../evil", Data: []byte("x")}})
				if err != nil {
					t.Fatalf("setup tarGzBytes: %v", err)
				}
				return bad
			},
			expectError:   true,
			errorContains: "path traversal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bundle := tc.setupBundle(t)
			err := ExtractBundle(bundle, dir)

			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for path traversal")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				for _, name := range tc.checkFiles {
					p := filepath.Join(dir, name)
					if _, err := os.Stat(p); err != nil {
						t.Fatalf("stat %s: %v", name, err)
					}
				}
			}
		})
	}
}

type tarEntry struct {
	Name string
	Data []byte
}

func tarGzBytes(entries []tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.Name, Mode: 0644, Size: int64(len(e.Data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
