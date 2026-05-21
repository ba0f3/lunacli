package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type HostEntry struct {
	Alias       string   `yaml:"alias"`
	Host        string   `yaml:"host"`
	Tags        []string `yaml:"tags"`
	Description string   `yaml:"description"`
}

type HostsConfig struct {
	Version int         `yaml:"version"`
	Hosts   []HostEntry `yaml:"hosts"`
}

func LoadHosts(dir string) (*HostsConfig, error) {
	path := filepath.Join(dir, "hosts.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &HostsConfig{Version: 1, Hosts: []HostEntry{}}, nil
		}
		return nil, err
	}
	var cfg HostsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
