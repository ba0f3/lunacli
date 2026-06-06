package ssh

import (
	"fmt"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

func loadInventoryEntry(configDir, alias, dialHost, port string) (*config.HostEntry, error) {
	if strings.TrimSpace(configDir) == "" {
		return nil, nil
	}
	cfg, err := config.LoadHosts(configDir)
	if err != nil {
		return nil, err
	}
	names := knownHostsLookupCandidates(alias, dialHost, port)
	return config.MatchHostEntry(cfg, names...), nil
}

func inventoryHasTrustedKey(configDir, alias, dialHost, port string) (bool, error) {
	entry, err := loadInventoryEntry(configDir, alias, dialHost, port)
	if err != nil || entry == nil {
		return false, err
	}
	return strings.TrimSpace(entry.HostKey) != "", nil
}

func VerifyHostKeyFromInventory(configDir, alias, dialHost, port string, key gossh.PublicKey) (bool, error) {
	entry, err := loadInventoryEntry(configDir, alias, dialHost, port)
	if err != nil || entry == nil {
		return false, err
	}
	trusted, err := entry.TrustedPublicKey()
	if err != nil {
		return false, err
	}
	return config.PublicKeysEqual(trusted, key), nil
}

func hostKeyAlgorithmsFromInventory(configDir, alias, dialHost, port string) ([]string, error) {
	entry, err := loadInventoryEntry(configDir, alias, dialHost, port)
	if err != nil || entry == nil {
		return nil, err
	}
	trusted, err := entry.TrustedPublicKey()
	if err != nil {
		return nil, nil
	}
	return []string{trusted.Type()}, nil
}

func inventoryAliases(configDir string) ([]string, error) {
	if strings.TrimSpace(configDir) == "" {
		return nil, nil
	}
	cfg, err := config.LoadHosts(configDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range cfg.Hosts {
		if strings.TrimSpace(entry.HostKey) == "" {
			continue
		}
		if alias := strings.TrimSpace(entry.Alias); alias != "" {
			out = append(out, alias)
		}
	}
	return out, nil
}

func inventoryTrustHint(configDir, alias string) string {
	if configDir == "" {
		return "add host_key to hosts.yml or run: ssh " + alias
	}
	return fmt.Sprintf("add host_key to %s/hosts.yml or run: luna ssh-debug %s on an interactive terminal to trust it", configDir, alias)
}
