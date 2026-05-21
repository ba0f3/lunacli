package ssh

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// ParseKnownHosts reads ~/.ssh/known_hosts and returns a deduplicated list of
// unhashed hostnames and IP addresses found in the file.
func ParseKnownHosts() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".ssh", "known_hosts")

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No known_hosts file, return empty list
		}
		return nil, err
	}
	defer f.Close()

	hostSet := make(map[string]struct{})
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split line by spaces. Format: [marker] hostnames keytype base64-key [comment]
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		hostField := parts[0]
		if strings.HasPrefix(hostField, "@") {
			// Skip markers and read the next field as hostnames
			if len(parts) < 4 {
				continue
			}
			hostField = parts[1]
		}

		// Hashed hosts start with |1|
		if strings.HasPrefix(hostField, "|1|") {
			continue // Skip hashed hosts as we can't list them
		}

		// Host field is a comma-separated list
		hosts := strings.Split(hostField, ",")
		for _, h := range hosts {
			// Remove port/brackets if present, e.g. [192.168.1.50]:2222
			h = strings.TrimPrefix(h, "[")
			if idx := strings.Index(h, "]:"); idx != -1 {
				h = h[:idx]
			}
			hostSet[h] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var result []string
	for h := range hostSet {
		result = append(result, h)
	}
	return result, nil
}
