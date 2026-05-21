package tools

import (
	"regexp"
	"strings"
)

var secretArgNames = []string{
	"password",
	"passwd",
	"pwd",
	"secret",
	"token",
	"apikey",
	"api-key",
	"access-key",
	"access_key",
	"private-key",
	"private_key",
	"credential",
	"credentials",
	"auth",
	"authorization",
}

var apkPackagePattern = regexp.MustCompile(`^(.+)-([0-9][^\s]*)`)

func redactSecretLikeArgs(command string) string {
	fields := strings.Fields(command)
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		key := strings.TrimLeft(field, "-")
		if idx := strings.Index(key, "="); idx >= 0 {
			name := key[:idx]
			if isSecretArgName(name) {
				prefix := field[:strings.Index(field, "=")+1]
				fields[i] = prefix + "[REDACTED]"
			}
			continue
		}
		if isSecretArgName(key) && i+1 < len(fields) {
			fields[i+1] = "[REDACTED]"
		}
	}
	return strings.Join(fields, " ")
}

func isSecretArgName(name string) bool {
	normalized := strings.ToLower(strings.Trim(name, " -_"))
	for _, candidate := range secretArgNames {
		if normalized == candidate || strings.Contains(normalized, candidate) {
			return true
		}
	}
	return false
}

func parseOSRelease(out string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[key] = strings.Trim(value, `"`)
	}
	return result
}

func parseDPKGPackages(out string) []InventoryPackage {
	return parseTabPackages("dpkg", out)
}

func parseRPMPackages(out string) []InventoryPackage {
	return parseTabPackages("rpm", out)
}

func parseAPKPackages(out string) []InventoryPackage {
	packages := []InventoryPackage{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		nameVersion := strings.Fields(line)[0]
		matches := apkPackagePattern.FindStringSubmatch(nameVersion)
		if len(matches) != 3 {
			continue
		}
		packages = append(packages, InventoryPackage{
			Manager: "apk",
			Name:    matches[1],
			Version: matches[2],
		})
	}
	return packages
}

func parseTabPackages(manager, out string) []InventoryPackage {
	packages := []InventoryPackage{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		pkg := InventoryPackage{Manager: manager, Name: parts[0], Version: parts[1]}
		if len(parts) > 2 {
			pkg.Arch = parts[2]
		}
		packages = append(packages, pkg)
	}
	return packages
}

func parseSystemdServices(out string) []InventoryService {
	services := []InventoryService{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		service := InventoryService{
			Name:        parts[0],
			LoadState:   parts[1],
			ActiveState: parts[2],
			SubState:    parts[3],
		}
		if len(parts) > 4 {
			service.Description = strings.Join(parts[4:], " ")
		}
		services = append(services, service)
	}
	return services
}

func parsePSProcesses(out string) []InventoryProcess {
	processes := []InventoryProcess{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		processes = append(processes, InventoryProcess{
			User:    parts[0],
			PID:     parts[1],
			CPU:     parts[2],
			Memory:  parts[3],
			Command: redactSecretLikeArgs(strings.Join(parts[4:], " ")),
		})
	}
	return processes
}

func parseSSPorts(out string) []InventoryPort {
	ports := []InventoryPort{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		port := InventoryPort{
			Protocol: parts[0],
			State:    parts[1],
			Local:    parts[4],
		}
		if len(parts) > 6 {
			port.Process = strings.Join(parts[6:], " ")
		}
		ports = append(ports, port)
	}
	return ports
}

func parseDockerContainers(out string) []InventoryContainer {
	containers := []InventoryContainer{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 4 || strings.TrimSpace(parts[0]) == "" {
			continue
		}
		containers = append(containers, InventoryContainer{
			Runtime: "docker",
			ID:      parts[0],
			Image:   parts[1],
			Name:    parts[2],
			State:   parts[3],
		})
	}
	return containers
}

func parseWazuhClientKeys(out string) WazuhHint {
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return WazuhHint{AgentID: parts[0], AgentName: parts[1]}
		}
	}
	return WazuhHint{}
}
