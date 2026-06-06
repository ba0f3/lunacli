package config

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gossh "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type HostEntry struct {
	Alias       string   `yaml:"alias"`
	Host        string   `yaml:"host"`
	HostKey     string   `yaml:"host_key,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

type HostsConfig struct {
	Version int         `yaml:"version"`
	Hosts   []HostEntry `yaml:"hosts"`
}

func LoadHosts(dir string) (*HostsConfig, error) {
	path := hostsPath(dir)
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
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	return &cfg, nil
}

func SaveHosts(dir string, cfg *HostsConfig) error {
	if cfg == nil {
		return fmt.Errorf("hosts config is nil")
	}
	if cfg.Version == 0 {
		cfg.Version = 1
	}
	path := hostsPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func UpsertHostEntry(dir string, entry HostEntry) error {
	cfg, err := LoadHosts(dir)
	if err != nil {
		return err
	}
	entry.Alias = strings.TrimSpace(entry.Alias)
	if entry.Alias == "" {
		return fmt.Errorf("host entry alias is required")
	}
	for i := range cfg.Hosts {
		if cfg.Hosts[i].Alias == entry.Alias {
			cfg.Hosts[i] = entry
			return SaveHosts(dir, cfg)
		}
	}
	cfg.Hosts = append(cfg.Hosts, entry)
	return SaveHosts(dir, cfg)
}

// MatchHostEntry finds an inventory row matching any of the given names or host targets.
func MatchHostEntry(cfg *HostsConfig, names ...string) *HostEntry {
	if cfg == nil {
		return nil
	}
	want := make(map[string]struct{})
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		want[strings.ToLower(name)] = struct{}{}
	}
	for i := range cfg.Hosts {
		entry := &cfg.Hosts[i]
		for _, candidate := range []string{entry.Alias, entry.Host, hostEntryBaseName(entry.Host)} {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}
			if _, ok := want[strings.ToLower(candidate)]; ok {
				return entry
			}
		}
	}
	return nil
}

func hostEntryBaseName(hostTarget string) string {
	_, host, _ := splitHostTarget(hostTarget)
	return host
}

func splitHostTarget(hostTarget string) (user, host, port string) {
	user = "root"
	hostTarget = strings.TrimSpace(hostTarget)
	if hostTarget == "" {
		return user, "", "22"
	}
	if at := strings.LastIndex(hostTarget, "@"); at >= 0 {
		user = hostTarget[:at]
		hostTarget = hostTarget[at+1:]
	}
	host = hostTarget
	port = "22"
	if strings.Contains(hostTarget, ":") {
		if h, p, err := splitHostPort(hostTarget); err == nil {
			host, port = h, p
		}
	}
	return user, host, port
}

func splitHostPort(hostPort string) (host, port string, err error) {
	if strings.HasPrefix(hostPort, "[") {
		if i := strings.Index(hostPort, "]:"); i >= 0 {
			return hostPort[1:i], hostPort[i+2:], nil
		}
	}
	i := strings.LastIndex(hostPort, ":")
	if i < 0 {
		return hostPort, "22", nil
	}
	return hostPort[:i], hostPort[i+1:], nil
}

// FormatHostKeyLine returns an OpenSSH authorized-keys style line (type + base64).
func FormatHostKeyLine(pub gossh.PublicKey) string {
	return pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal())
}

// TrustedPublicKey parses HostKey as an SSH public key.
func (e *HostEntry) TrustedPublicKey() (gossh.PublicKey, error) {
	line := strings.TrimSpace(e.HostKey)
	if line == "" {
		return nil, fmt.Errorf("host %q has no host_key", e.Alias)
	}
	if !strings.Contains(line, " ") {
		line = "ssh-rsa " + line
	}
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse host_key for %q: %w", e.Alias, err)
	}
	return pub, nil
}

// PublicKeysEqual reports whether two SSH public keys are identical.
func PublicKeysEqual(a, b gossh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// PromptAddHostEntry asks on an interactive terminal to persist a new inventory row.
func PromptAddHostEntry(r io.Reader, w io.Writer, dir, alias, hostTarget string, pub gossh.PublicKey) (bool, error) {
	alias = strings.TrimSpace(alias)
	hostTarget = strings.TrimSpace(hostTarget)
	if alias == "" {
		alias = hostEntryBaseName(hostTarget)
	}
	if alias == "" {
		return false, fmt.Errorf("cannot derive alias for host target %q", hostTarget)
	}
	if hostTarget == "" {
		hostTarget = alias
	}

	keyLine := FormatHostKeyLine(pub)
	fmt.Fprintf(w, "\nHost %q is not trusted via ~/.ssh/known_hosts or hosts.yml.\n", alias)
	fmt.Fprintf(w, "  host:      %s\n", hostTarget)
	fmt.Fprintf(w, "  host_key:  %s\n", keyLine)
	fmt.Fprintf(w, "  fingerprint: SHA256:%s\n", gossh.FingerprintSHA256(pub))
	fmt.Fprint(w, "Add to hosts.yml? [y/N]: ")

	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		return false, nil
	}

	entry := HostEntry{
		Alias:   alias,
		Host:    hostTarget,
		HostKey: keyLine,
	}
	if err := UpsertHostEntry(dir, entry); err != nil {
		return false, err
	}
	fmt.Fprintf(w, "Added %q to %s\n", alias, hostsPath(dir))
	return true, nil
}

func hostsPath(dir string) string {
	return filepath.Join(dir, "hosts.yml")
}
