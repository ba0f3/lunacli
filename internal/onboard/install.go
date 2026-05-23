package onboard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ba0f3/lunacli/internal/config"
)

type WriteMode int

const (
	WriteMerge WriteMode = iota
	WriteReplace
)

func WriteFile(mode WriteMode, path string, data []byte, perm os.FileMode) (bool, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	if mode == WriteMerge {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			if os.IsExist(err) {
				return false, nil
			}
			return false, fmt.Errorf("create file %s: %w", path, err)
		}
		_, writeErr := f.Write(data)
		closeErr := f.Close()
		if writeErr != nil {
			return false, fmt.Errorf("write file %s: %w", path, writeErr)
		}
		if closeErr != nil {
			return false, fmt.Errorf("close file %s: %w", path, closeErr)
		}
		return true, nil
	}

	if err := os.WriteFile(path, data, perm); err != nil {
		return false, fmt.Errorf("write file %s: %w", path, err)
	}
	return true, nil
}

func WriteConfigJSON(path string, mode WriteMode, fs config.FileSettings) (bool, error) {
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	wrote, err := WriteFile(mode, path, data, 0644)
	if err != nil {
		return false, fmt.Errorf("write config %s: %w", path, err)
	}
	return wrote, nil
}

// InstallBundle writes embedded policy files into layout.PolicyDir honoring write mode.
func InstallBundle(mode WriteMode, ly Layout) (map[string]bool, error) {
	entries, err := BundleEntries(embeddedBundle)
	if err != nil {
		return nil, fmt.Errorf("bundle entries: %w", err)
	}
	if err := os.MkdirAll(ly.PolicyDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", ly.PolicyDir, err)
	}
	written := make(map[string]bool)
	for name, data := range entries {
		path := filepath.Join(ly.PolicyDir, name)
		if !isWithinBaseDir(ly.PolicyDir, path) {
			return nil, fmt.Errorf("invalid bundle output path: %q", name)
		}
		ok, err := WriteFile(mode, path, data, 0644)
		if err != nil {
			return nil, fmt.Errorf("install file %s: %w", path, err)
		}
		written[name] = ok
	}
	return written, nil
}
