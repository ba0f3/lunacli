package policy

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func LoadPolicy(dir string) (*Policy, error) {
	path := filepath.Join(dir, "policy.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pol Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}
