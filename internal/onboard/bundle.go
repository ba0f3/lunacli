package onboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractBundle unpacks a gzip tarball into destDir (only policy.yml and hosts.yml).
func ExtractBundle(bundle []byte, destDir string) error {
	entries, err := BundleEntries(bundle)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	for name, data := range entries {
		dest := filepath.Join(destDir, name)
		if !isWithinBaseDir(destDir, dest) {
			return fmt.Errorf("invalid output path: %q", name)
		}
		if err := os.WriteFile(dest, data, 0644); err != nil {
			return err
		}
	}
	return nil
}

// BundleEntries reads allowed files from a gzip tarball.
func BundleEntries(bundle []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gr.Close() }() //nolint:errcheck // gzip reader close after read

	out := make(map[string][]byte)
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if err := validateTarName(hdr.Name); err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out[hdr.Name] = data
	}
}

func isWithinBaseDir(baseDir, targetPath string) bool {
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func validateTarName(name string) error {
	name = filepath.Clean(name)
	if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
		return fmt.Errorf("invalid tar entry: %q", name)
	}
	switch name {
	case "policy.yml", "hosts.yml":
		return nil
	default:
		return fmt.Errorf("unexpected tar entry: %q", name)
	}
}
