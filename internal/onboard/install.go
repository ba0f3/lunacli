package onboard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

type WriteMode int

const (
	WriteMerge WriteMode = iota
	WriteReplace
)

func WriteFile(mode WriteMode, path string, data []byte, perm os.FileMode) (bool, error) {
	if mode == WriteMerge {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return false, err
	}
	return true, nil
}

func WriteConfigJSON(path string, mode WriteMode, fs config.FileSettings) (bool, error) {
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	return WriteFile(mode, path, data, 0644)
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

// InstallBundle writes embedded policy files into layout.PolicyDir honoring write mode.
func InstallBundle(mode WriteMode, ly Layout) (map[string]bool, error) {
	entries, err := BundleEntries(embeddedBundle)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ly.PolicyDir, 0755); err != nil {
		return nil, err
	}
	written := make(map[string]bool)
	for name, data := range entries {
		path := filepath.Join(ly.PolicyDir, name)
		if !isWithinBaseDir(ly.PolicyDir, path) {
			return nil, fmt.Errorf("invalid bundle output path: %q", name)
		}
		ok, err := WriteFile(mode, path, data, 0644)
		if err != nil {
			return nil, err
		}
		written[name] = ok
	}
	return written, nil
}
