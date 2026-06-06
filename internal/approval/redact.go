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
var authorizationHeader = regexp.MustCompile(`(?i)(authorization|proxy-authorization):`)
var singleQuotedAuthorizationHeader = regexp.MustCompile(`(?i)('(?:authorization|proxy-authorization):)[^']*`)
var doubleQuotedAuthorizationHeader = regexp.MustCompile(`(?i)("(?:authorization|proxy-authorization):)[^"]*`)
var singleQuotedAuthorizationValue = regexp.MustCompile(`(?i)((?:authorization|proxy-authorization):)'[^']*'`)
var doubleQuotedAuthorizationValue = regexp.MustCompile(`(?i)((?:authorization|proxy-authorization):)"[^"]*"`)
var singleQuotedCredentialArg = regexp.MustCompile(`(?i)((?:-u|--user|--proxy-user)\s+)'[^']*'`)
var doubleQuotedCredentialArg = regexp.MustCompile(`(?i)((?:-u|--user|--proxy-user)\s+)"[^"]*"`)
var singleQuotedAttachedCredential = regexp.MustCompile(`(?i)((?:-u|--user=|--proxy-user=))'[^']*'`)
var doubleQuotedAttachedCredential = regexp.MustCompile(`(?i)((?:-u|--user=|--proxy-user=))"[^"]*"`)
var urlUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`)

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
	command = singleQuotedAuthorizationHeader.ReplaceAllString(command, `$1 [REDACTED]`)
	command = doubleQuotedAuthorizationHeader.ReplaceAllString(command, `$1 [REDACTED]`)
	command = singleQuotedAuthorizationValue.ReplaceAllString(command, `$1 [REDACTED]`)
	command = doubleQuotedAuthorizationValue.ReplaceAllString(command, `$1 [REDACTED]`)
	command = singleQuotedCredentialArg.ReplaceAllString(command, `$1[REDACTED]`)
	command = doubleQuotedCredentialArg.ReplaceAllString(command, `$1[REDACTED]`)
	command = singleQuotedAttachedCredential.ReplaceAllString(command, `$1[REDACTED]`)
	command = doubleQuotedAttachedCredential.ReplaceAllString(command, `$1[REDACTED]`)
	command = urlUserinfo.ReplaceAllString(command, `$1[REDACTED]@`)
	fields := strings.Fields(command)
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		if authorizationHeader.MatchString(field) && strings.Contains(field, "[REDACTED]") {
			continue
		}
		if field == "-u" || field == "--user" || field == "--proxy-user" {
			if i+1 < len(fields) {
				fields[i+1] = "[REDACTED]"
			}
			continue
		}
		if prefix, _, ok := splitCredentialOption(field); ok {
			fields[i] = prefix + "[REDACTED]"
			continue
		}
		if field == "-H" || field == "--header" || field == "--proxy-header" {
			if i+1 < len(fields) && authorizationHeader.MatchString(fields[i+1]) {
				fields[i+1] = redactAuthorizationHeader(fields[i+1])
			}
			continue
		}
		if prefix, header, ok := splitHeaderOption(field); ok && authorizationHeader.MatchString(header) {
			fields[i] = prefix + redactAuthorizationHeader(header)
			continue
		}
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
	var redacted []string
	for _, field := range fields {
		if field != "" {
			redacted = append(redacted, field)
		}
	}
	return strings.Join(redacted, " ")
}

func redactAuthorizationHeader(header string) string {
	header = strings.Trim(header, `"'`)
	loc := authorizationHeader.FindStringIndex(header)
	if loc == nil {
		return "[REDACTED]"
	}
	return header[:loc[1]] + " [REDACTED]"
}

func splitCredentialOption(field string) (prefix, credential string, ok bool) {
	for _, option := range []string{"--user=", "--proxy-user="} {
		if strings.HasPrefix(field, option) {
			return option, strings.TrimPrefix(field, option), true
		}
	}
	if strings.HasPrefix(field, "-u") && len(field) > 2 {
		return "-u", strings.TrimPrefix(field, "-u"), true
	}
	return "", "", false
}

func splitHeaderOption(field string) (prefix, header string, ok bool) {
	for _, option := range []string{"--header=", "--proxy-header="} {
		if strings.HasPrefix(field, option) {
			return option, strings.TrimPrefix(field, option), true
		}
	}
	if strings.HasPrefix(field, "-H") && len(field) > 2 {
		return "-H", strings.TrimPrefix(field, "-H"), true
	}
	return "", "", false
}
