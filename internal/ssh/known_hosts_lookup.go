package ssh

import (
	"net"
	"strings"
)

// knownHostsLookupCandidates returns host names tried for known_hosts matching,
// in OpenSSH-like order: HostKeyAlias, config Host label, resolved HostName, and
// any SSH config alias that resolves to the same dial target.
func knownHostsLookupCandidates(alias, dialHost, port string) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, existing := range out {
			if existing == s {
				return
			}
		}
		out = append(out, s)
	}

	add(KnownHostsHost(alias, dialHost))
	if alias != dialHost {
		add(alias)
	}
	add(dialHost)
	for _, name := range reverseDNSHostCandidates(dialHost) {
		add(name)
	}

	for _, c := range sshConfigCandidatesForDialHost(dialHost, port) {
		add(KnownHostsHost(c.label, c.host))
		add(c.label)
	}
	return out
}

func reverseDNSHostCandidates(host string) []string {
	if net.ParseIP(strings.TrimSpace(host)) == nil {
		return nil
	}
	names, err := net.LookupAddr(host)
	if err != nil || len(names) == 0 {
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, existing := range out {
			if existing == s {
				return
			}
		}
		out = append(out, s)
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		add(name)
		if i := strings.IndexByte(name, '.'); i > 0 {
			add(name[:i])
		}
	}
	return out
}

func sshConfigCandidatesForDialHost(dialHost, port string) []sshHostCandidate {
	candidates, err := sshConfigHostCandidates()
	if err != nil {
		return nil
	}
	var out []sshHostCandidate
	seen := make(map[string]struct{})
	add := func(c sshHostCandidate) {
		key := c.label + "\t" + c.host + "\t" + c.port
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	for _, c := range candidates {
		if c.port != port {
			continue
		}
		if c.host == dialHost {
			add(c)
			continue
		}
		// Match aliases whose resolved dial IP equals dialHost (e.g. Tailscale IP
		// for an ssh config Host whose HostName is a DNS name).
		if ip, err := resolveTargetIP(c.host, c.port); err == nil && ip == dialHost {
			add(c)
		}
	}
	return out
}

// HasKnownHostEntryForTarget reports whether khPath or hosts.yml contains a trusted
// key for any lookup name associated with alias@dialHost:port.
func HasKnownHostEntryForTarget(configDir, khPath, alias, dialHost, port string) (bool, error) {
	for _, host := range knownHostsLookupCandidates(alias, dialHost, port) {
		ok, err := HasKnownHostEntry(khPath, host, port)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return inventoryHasTrustedKey(configDir, alias, dialHost, port)
}

// HostKeyAlgorithmsForTarget returns pinned host-key algorithms from ~/.ssh/known_hosts
// or, as a fallback, hosts.yml for alias@dialHost:port.
func HostKeyAlgorithmsForTarget(configDir, khPath, alias, dialHost, port string) ([]string, error) {
	for _, host := range knownHostsLookupCandidates(alias, dialHost, port) {
		algos, err := HostKeyAlgorithmsForKnownHost(khPath, host, port)
		if err != nil {
			return nil, err
		}
		if len(algos) > 0 {
			return algos, nil
		}
	}
	return hostKeyAlgorithmsFromInventory(configDir, alias, dialHost, port)
}
