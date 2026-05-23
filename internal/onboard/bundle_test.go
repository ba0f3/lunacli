package onboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractBundle_safeAndWritesFiles(t *testing.T) {
	dir := t.TempDir()
	if err := ExtractBundle(embeddedBundle, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"policy.yml", "hosts.yml"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
	}
}

func TestExtractBundle_rejectsTraversal(t *testing.T) {
	bad, err := tarGzBytes([]tarEntry{{Name: "../evil", Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtractBundle(bad, t.TempDir()); err == nil {
		t.Fatal("expected error for path traversal")
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
