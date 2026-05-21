package approval

import (
	"regexp"
	"strings"
)

const RedactionVersion = "luna.redact.v1"

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

// envAssignLine matches a full line that is only an env assignment, optionally
// prefixed by export (same shape as inventory-style KEY=value redaction).
var envAssignLine = regexp.MustCompile(`^(export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// RedactSecrets returns input with secret-like command flags and env assignments
// replaced by [REDACTED] using the same flag-name inventory as inventory_parse.
func RedactSecrets(input string) string {
	if input == "" {
		return input
	}
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = redactLine(line)
	}
	return strings.Join(lines, "\n")
}

func redactLine(line string) string {
	line = strings.TrimSuffix(line, "\r")
	trimmed := strings.TrimSpace(line)
	if m := envAssignLine.FindStringSubmatch(trimmed); m != nil {
		name := m[2]
		if isSecretEnvName(name) {
			redacted := m[1] + name + "=[REDACTED]"
			idx := strings.Index(line, trimmed)
			if idx < 0 {
				return redacted
			}
			return line[:idx] + redacted + line[idx+len(trimmed):]
		}
		return line
	}
	return redactSecretLikeArgs(line)
}

func isSecretEnvName(name string) bool {
	normalized := strings.ToLower(strings.Trim(name, " -_"))
	for _, candidate := range secretArgNames {
		if normalized == candidate || strings.Contains(normalized, candidate) {
			return true
		}
	}
	return false
}

func isSecretArgName(name string) bool {
	n := strings.TrimLeft(name, "-")
	// curl -H "Name: value" splits into separate fields; a header label ends with ':' and must not
	// trigger the generic "auth" / "authorization" heuristics on the following token.
	if strings.HasSuffix(strings.ToLower(n), ":") {
		return false
	}
	return isSecretEnvName(n)
}

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
