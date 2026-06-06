package ssh

import (
	"bufio"
	"os"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

// ParseKnownHosts reads ~/.ssh/known_hosts and hosts.yml inventory entries with
// host_key set, returning dialable host identifiers for execute_remote.
func ParseKnownHosts() ([]string, error) {
	configDir := ""
	if settings, err := config.LoadSettings(); err == nil {
		configDir = settings.ConfigDir()
	}
	return parseTrustedHosts(configDir)
}

func parseTrustedHosts(configDir string) ([]string, error) {
	path, err := defaultKnownHostsPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return discoverKnownHostNames(configDir, path, nil)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	hostSet := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		for _, h := range parsePlainKnownHostsLine(scanner.Text()) {
			hostSet[h] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	plain := make([]string, 0, len(hostSet))
	for h := range hostSet {
		plain = append(plain, h)
	}
	return discoverKnownHostNames(configDir, path, plain)
}

func parsePlainKnownHostsLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil
	}

	hostField := parts[0]
	if strings.HasPrefix(hostField, "@") {
		if len(parts) < 4 {
			return nil
		}
		hostField = parts[1]
	}
	if strings.HasPrefix(hostField, "|") {
		return nil
	}

	var hosts []string
	for _, h := range strings.Split(hostField, ",") {
		h = strings.TrimPrefix(h, "[")
		if idx := strings.Index(h, "]:"); idx != -1 {
			h = h[:idx]
		}
		h = strings.TrimSpace(h)
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
