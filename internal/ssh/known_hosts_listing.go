package ssh

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var knownHostsCommentIP = regexp.MustCompile(`#\s*(\d+\.\d+\.\d+\.\d+):\d+`)

func discoverKnownHostNames(configDir, khPath string, plain []string) ([]string, error) {
	hostSet := make(map[string]struct{})
	for _, h := range plain {
		hostSet[h] = struct{}{}
	}

	candidates, err := sshConfigHostCandidates()
	if err != nil {
		return nil, err
	}
	for _, c := range candidates {
		ok, err := HasKnownHostEntryForTarget(configDir, khPath, c.label, c.host, c.port)
		if err != nil {
			return nil, err
		}
		if ok {
			hostSet[c.label] = struct{}{}
			hostSet[c.host] = struct{}{}
		}
	}

	for _, name := range listingNameCandidates(plain, khPath) {
		if _, ok := hostSet[name]; ok {
			continue
		}
		ok, err := HasKnownHostEntry(khPath, name, "22")
		if err != nil {
			return nil, err
		}
		if ok {
			hostSet[name] = struct{}{}
		}
	}

	aliases, err := inventoryAliases(configDir)
	if err != nil {
		return nil, err
	}
	for _, alias := range aliases {
		hostSet[alias] = struct{}{}
	}

	result := make([]string, 0, len(hostSet))
	for h := range hostSet {
		result = append(result, h)
	}
	return result, nil
}

func listingNameCandidates(plain []string, khPath string) []string {
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

	if candidates, err := sshConfigHostCandidates(); err == nil {
		for _, c := range candidates {
			add(c.label)
			add(c.host)
			add(KnownHostsHost(c.label, c.host))
		}
	}

	for _, name := range etcHostsNames() {
		add(name)
	}
	for _, name := range tailscaleHostCandidates() {
		add(name)
	}

	for _, h := range plain {
		add(h)
		if net.ParseIP(h) != nil {
			for _, name := range reverseDNSHostCandidates(h) {
				add(name)
			}
		}
	}
	for _, ip := range knownHostsCommentIPs(khPath) {
		add(ip)
		for _, name := range reverseDNSHostCandidates(ip) {
			add(name)
		}
	}
	return out
}

func etcHostsNames() []string {
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		for _, existing := range out {
			if existing == s {
				return
			}
		}
		out = append(out, s)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields[1:] {
			add(name)
			if i := strings.IndexByte(name, '.'); i > 0 {
				add(name[:i])
			}
		}
	}
	return out
}

func tailscaleHostCandidates() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
	if err != nil {
		return nil
	}
	var data struct {
		Peer map[string]struct {
			HostName string `json:"HostName"`
			DNSName  string `json:"DNSName"`
		} `json:"Peer"`
		Self struct {
			HostName string `json:"HostName"`
			DNSName  string `json:"DNSName"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil
	}
	var names []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ".")
		if s == "" {
			return
		}
		for _, existing := range names {
			if existing == s {
				return
			}
		}
		names = append(names, s)
	}
	add(data.Self.HostName)
	addShortDNSName(add, data.Self.DNSName)
	for _, p := range data.Peer {
		add(p.HostName)
		addShortDNSName(add, p.DNSName)
	}
	return names
}

func addShortDNSName(add func(string), dnsName string) {
	dnsName = strings.TrimSpace(dnsName)
	dnsName = strings.TrimSuffix(dnsName, ".")
	if dnsName == "" {
		return
	}
	add(dnsName)
	if i := strings.IndexByte(dnsName, '.'); i > 0 {
		add(dnsName[:i])
	}
}

func knownHostsCommentIPs(khPath string) []string {
	f, err := os.Open(khPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []string
	add := func(ip string) {
		for _, existing := range out {
			if existing == ip {
				return
			}
		}
		out = append(out, ip)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := knownHostsCommentIP.FindStringSubmatch(scanner.Text())
		if len(m) == 2 {
			add(m[1])
		}
	}
	return out
}
