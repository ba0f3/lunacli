package ssh

import (
	"bufio"
	"os"
	"strings"
)

// ParseKnownHosts reads ~/.ssh/known_hosts and returns host identifiers the user
// can dial with execute_remote: plain (unhashed) entries from the file, plus SSH
// config Host aliases whose resolved HostName matches a plain or OpenSSH-hashed
// (|1|) known_hosts line.
func ParseKnownHosts() ([]string, error) {
	path, err := defaultKnownHostsPath()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return matchKnownHostsFromSSHConfig(path, nil)
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
	return matchKnownHostsFromSSHConfig(path, plain)
}

func matchKnownHostsFromSSHConfig(khPath string, plain []string) ([]string, error) {
	hostSet := make(map[string]struct{})
	for _, h := range plain {
		hostSet[h] = struct{}{}
	}

	candidates, err := sshConfigHostCandidates()
	if err != nil {
		return nil, err
	}
	for _, c := range candidates {
		ok, err := HasKnownHostEntry(khPath, c.host, c.port)
		if err != nil {
			return nil, err
		}
		if ok {
			hostSet[c.label] = struct{}{}
		}
	}

	result := make([]string, 0, len(hostSet))
	for h := range hostSet {
		result = append(result, h)
	}
	return result, nil
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
