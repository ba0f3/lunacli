package ssh

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
)

func loadUserSSHConfig() (*ssh_config.Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".ssh", "config")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ssh_config.Decode(f)
}

// resolveSSHConfigHost maps an SSH config Host alias to the HostName and Port
// used for dialing and known_hosts matching (OpenSSH hashes the resolved target).
func resolveSSHConfigHost(alias, port string) (host, portOut string) {
	cfg, err := loadUserSSHConfig()
	if err != nil || cfg == nil {
		host = strings.TrimSpace(alias)
		portOut = port
		if portOut == "" {
			portOut = "22"
		}
		return host, portOut
	}
	return resolveSSHConfigHostFrom(cfg, alias, port)
}

func resolveSSHConfigHostFrom(cfg *ssh_config.Config, alias, port string) (host, portOut string) {
	host = strings.TrimSpace(alias)
	portOut = port
	if host == "" {
		if portOut == "" {
			portOut = "22"
		}
		return host, portOut
	}
	if hn, err := cfg.Get(alias, "HostName"); err == nil && strings.TrimSpace(hn) != "" {
		host = strings.TrimSpace(hn)
	}
	if portOut == "" || portOut == "22" {
		if p, err := cfg.Get(alias, "Port"); err == nil && strings.TrimSpace(p) != "" {
			portOut = strings.TrimSpace(p)
		}
	}
	if portOut == "" {
		portOut = "22"
	}
	return host, portOut
}

type sshHostCandidate struct {
	label string // ssh config Host pattern (what the user types)
	host  string // resolved HostName
	port  string
}

func sshConfigHostCandidates() ([]sshHostCandidate, error) {
	cfg, err := loadUserSSHConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	var out []sshHostCandidate
	seen := make(map[string]struct{})
	for _, block := range cfg.Hosts {
		for _, pat := range block.Patterns {
			if pat == nil {
				continue
			}
			label := strings.TrimSpace(pat.String())
			if strings.HasPrefix(label, "!") {
				label = label[1:]
			}
			if !isConcreteSSHHostPattern(label) {
				continue
			}
			host, port := resolveSSHConfigHostFrom(cfg, label, "22")
			key := label + "\t" + host + "\t" + port
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, sshHostCandidate{label: label, host: host, port: port})
		}
	}
	return out, nil
}

func isConcreteSSHHostPattern(pat string) bool {
	if pat == "" {
		return false
	}
	for _, r := range pat {
		switch r {
		case '*', '?', '!':
			return false
		}
	}
	return true
}

func defaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

func knownHostsCheckAddress(host, port string) string {
	return net.JoinHostPort(host, port)
}
