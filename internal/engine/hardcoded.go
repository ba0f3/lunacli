package engine

import (
	"path/filepath"
	"regexp"
	"strings"
)

const maxCommandLen = 4096

var forbiddenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*|-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+/(?:\s+|$)`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\bdd\s+if=`),
	regexp.MustCompile(`(?i)>\s*/dev/sd[a-z]`),
	regexp.MustCompile(`(?i)>\s*/dev/nvme`),
	regexp.MustCompile(`(?i)>\s*/dev/hd[a-z]`),
	regexp.MustCompile(`(?i)>\s*/dev/mapper/`),
	regexp.MustCompile(`(?i)\bshred\b`),
	regexp.MustCompile(`(?i)\bwipefs\b`),
	regexp.MustCompile(`(?i)\bfdisk\b`),
	regexp.MustCompile(`(?i)\bparted\b`),
	regexp.MustCompile(`(?i)\bcrypt\w*\s+luksFormat`),
	regexp.MustCompile(`(?i)\bdebugfs\b`),
	regexp.MustCompile(`(?i)\btune2fs\b`),
	regexp.MustCompile(`(?i)\bresize2fs\b`),
	regexp.MustCompile(`(?i)\bxfs_growfs\b`),
	regexp.MustCompile(`(?i)\bfsck\b`),
	regexp.MustCompile(`(?i)\bbadblocks\b`),
	regexp.MustCompile(`(?i)\bhdparm\b`),
	regexp.MustCompile(`(?i):\(\)\s*\{`),
	regexp.MustCompile(`(?i)\biptables\s+-F\b`),
	regexp.MustCompile(`(?i)\bnft\s+flush\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])passwd\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])(?:useradd|userdel|usermod)\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])(?:groupadd|groupdel|groupmod)\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])visudo\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])sudo\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])su\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])doas\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])insmod\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])modprobe\b`),
	regexp.MustCompile(`(?i)(?:^|[|&;])rmmod\b`),
	regexp.MustCompile(`(?i)\bnc\s+.*-[el]`),
	regexp.MustCompile(`(?i)\bncat\s+.*-[el]`),
	regexp.MustCompile(`(?i)\bsocat\b`),
	regexp.MustCompile(`(?i)/dev/tcp/`),
	regexp.MustCompile(`(?i)/dev/udp/`),
	regexp.MustCompile(`(?i)\bbash\s+-i\b`),
	regexp.MustCompile(`(?i)\bpython[23]?\s+.*-[ci]\b`),
	regexp.MustCompile(`(?i)\bperl\s+(?:.*?\s)?-[a-z]*[ei][^\s]*(?:\s|$)`),
	regexp.MustCompile(`(?i)\bruby\s+.*-[ei]\b`),
	regexp.MustCompile(`(?i)\bnode\s+.*-[ei]\b`),
	regexp.MustCompile(`(?i)\blua\b`),
	regexp.MustCompile(`(?i)^python[23]?\s+\S`),
	regexp.MustCompile(`(?i)^ruby\s+\S`),
	regexp.MustCompile(`(?i)^node\s+\S`),
	regexp.MustCompile(`(?i)^perl\s+\S`),
	regexp.MustCompile(`(?i)^php\s+\S`),
	regexp.MustCompile(`(?i)^Rscript\s+\S`),
	regexp.MustCompile(`(?i)^(?:bash|sh|dash|zsh|ksh|csh|tcsh)\s+\S`),
	regexp.MustCompile(`(?i)^exec\s+\S`),
	regexp.MustCompile(`(?i)\bfind\s+.*-delete\b`),
	regexp.MustCompile(`(?i)\bfind\s+.*-exec\s+rm\b`),
	regexp.MustCompile(`(?i)\bchmod\s+(?:[0-7]*777|[0-7]*777[0-7]*)\s+/(?:etc|bin|sbin|usr)\b`),
	regexp.MustCompile(`(?i)\btee\s+/(?:etc/passwd|etc/shadow|etc/sudoers|etc/ssh)\b`),
}

var mutatingFlagPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bcurl\s+.*(?:-[A-Za-z]*d|--data|--data-binary|--data-raw|--data-urlencode|--post-file|-T\s|--upload-file)\b`),
	regexp.MustCompile(`(?i)\bcurl\s+.*(?:-o\s|--output|-O)\b`),
	regexp.MustCompile(`(?i)\bwget\s+.*(?:--post-data|--post-file|--body-data|--body-file|-O\s|--output-document)\b`),
	regexp.MustCompile(`(?i)\bfind\s+.*-(?:exec|ok)\b`),
	regexp.MustCompile(`(?i)\bsed\s+(?:.*?\s)?(?:-[a-z]*i[^\s]*|--in-place)(?:\s|$)`),
	regexp.MustCompile(`(?i)\bawk\s+(?:.*?\s)?-[a-z]*i[^\s]*(?:\s|$)`),
}

var databaseClients = map[string]struct{}{
	"clickhouse-client": {}, "duckdb": {}, "mariadb": {}, "mongo": {}, "mongosh": {},
	"mysql": {}, "psql": {}, "sqlite": {}, "sqlite3": {},
}

var databaseMutationPattern = regexp.MustCompile(`(?i)\b(?:update|delete\s+from|drop|create)\b`)

func unescape(s string) string {
	// ⚡ Bolt Optimization: Early return if no backslash is found to avoid string builder allocation.
	if !strings.ContainsRune(s, '\\') {
		return s
	}

	var b strings.Builder
	b.Grow(len(s)) // ⚡ Bolt Optimization: Pre-allocate capacity to avoid growing the builder.
	escaping := false
	for _, ch := range s {
		if escaping {
			b.WriteRune(ch)
			escaping = false
		} else if ch == '\\' {
			escaping = true
		} else {
			b.WriteRune(ch)
		}
	}
	if escaping {
		b.WriteRune('\\')
	}
	return b.String()
}

func unwrapCommand(args []string) []string {
	if len(args) == 0 {
		return args
	}
	for {
		if len(args) == 0 {
			return args
		}
		cmd := args[0]
		if cmd == "command" || cmd == "nohup" {
			if cmd == "command" && containsArg(args[1:], "-v", "-V") {
				return args
			}
			i := 1
			for i < len(args) && strings.HasPrefix(args[i], "-") {
				i++
			}
			if i >= len(args) {
				return args
			}
			args = args[i:]
			continue
		}
		if cmd == "timeout" {
			i := timeoutDurationIndex(args)
			if i < len(args) {
				i++
			}
			if i >= len(args) {
				return args
			}
			args = args[i:]
			continue
		}
		if cmd == "env" {
			i := 1
			for i < len(args) {
				arg := args[i]
				if strings.Contains(arg, "=") {
					i++
					continue
				}
				if strings.HasPrefix(arg, "-") {
					i++
					continue
				}
				break
			}
			if i >= len(args) {
				return args
			}
			args = args[i:]
			continue
		}
		if cmd == "xargs" {
			i := 1
			for i < len(args) {
				arg := args[i]
				if strings.HasPrefix(arg, "-") {
					i++
					continue
				}
				break
			}
			if i >= len(args) {
				return args
			}
			args = args[i:]
			continue
		}
		break
	}
	return args
}

func timeoutDurationIndex(args []string) int {
	i := 1
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			return i + 1
		}
		if arg == "-s" || arg == "--signal" || arg == "-k" || arg == "--kill-after" {
			i += 2
			continue
		}
		if strings.HasPrefix(arg, "--signal=") || strings.HasPrefix(arg, "--kill-after=") ||
			(strings.HasPrefix(arg, "-s") && len(arg) > 2) || (strings.HasPrefix(arg, "-k") && len(arg) > 2) ||
			arg == "--foreground" || arg == "--preserve-status" || arg == "--verbose" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			i++
			continue
		}
		return i
	}
	return i
}

func isLiteralInspectionCommand(command string) bool {
	switch filepath.Base(strings.ToLower(command)) {
	case "echo", "printf", "grep", "egrep", "fgrep":
		return true
	default:
		return false
	}
}

func hasMutatingFlagPatterns(command string) bool {
	switch filepath.Base(strings.ToLower(command)) {
	case "curl", "wget", "find", "sed", "awk":
		return true
	default:
		return false
	}
}

func isSemanticMutation(args []string) bool {
	if len(args) == 0 {
		return false
	}
	command := filepath.Base(strings.ToLower(args[0]))
	switch command {
	case "hostname":
		// hostname uses exact case flags (e.g. -A vs -a), pass raw args
		return isHostnameMutation(args[1:])
	case "ss":
		// ss uses mixed case options internally, pass raw args
		return isSSMutation(args[1:])
	case "date", "journalctl", "ip", "sort", "uniq", "diff":
		// ⚡ Bolt Optimization: Only allocate and calculate lowercase args
		// if we are actually checking one of the target commands.
		lowerArgs := make([]string, len(args)-1)
		for i, arg := range args[1:] {
			lowerArgs[i] = strings.ToLower(arg)
		}
		switch command {
		case "date":
			return containsOption(lowerArgs, "-s", "--set")
		case "journalctl":
			return containsArgStartingWith(lowerArgs, "--vacuum") ||
				containsArgPrefix(lowerArgs, "--cursor-file") ||
				containsArg(lowerArgs, "--rotate", "--flush", "--sync", "--relinquish-var",
					"--smart-relinquish-var", "--update-catalog", "--setup-keys")
		case "ip":
			return isIPMutation(lowerArgs)
		case "sort":
			return containsOption(lowerArgs, "-o", "--output")
		case "uniq":
			return uniqHasOutput(lowerArgs)
		case "diff":
			return containsArgPrefix(lowerArgs, "--output")
		}
	}
	return false
}

func isSSMutation(args []string) bool {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "--kill" || lower == "--diag" || strings.HasPrefix(lower, "--diag=") {
			return true
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			options := strings.TrimPrefix(arg, "-")
			if strings.ContainsRune(options, 'K') || strings.ContainsRune(options, 'D') {
				return true
			}
		}
	}
	return false
}

func containsOption(args []string, short, long string) bool {
	shortName := strings.TrimPrefix(short, "-")
	for _, arg := range args {
		if arg == short || strings.HasPrefix(arg, short) || arg == long || strings.HasPrefix(arg, long+"=") ||
			(strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(strings.TrimPrefix(arg, "-"), shortName)) {
			return true
		}
	}
	return false
}

func uniqHasOutput(args []string) bool {
	positionals := 0
	for _, arg := range args {
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		positionals++
	}
	return positionals >= 2
}

func isHostnameMutation(args []string) bool {
	readOnlyFlags := map[string]struct{}{
		"-a": {}, "-A": {}, "-d": {}, "-f": {}, "-i": {}, "-I": {}, "-s": {}, "-y": {},
		"--alias": {}, "--all-fqdns": {}, "--domain": {}, "--fqdn": {}, "--ip-address": {},
		"--all-ip-addresses": {}, "--short": {}, "--yp": {}, "--nis": {}, "--help": {}, "--version": {},
	}
	for _, arg := range args {
		if _, ok := readOnlyFlags[arg]; !ok {
			return true
		}
	}
	return false
}

func containsArgStartingWith(args []string, prefixes ...string) bool {
	for _, arg := range args {
		for _, prefix := range prefixes {
			if strings.HasPrefix(arg, prefix) {
				return true
			}
		}
	}
	return false
}

func containsArg(args []string, values ...string) bool {
	for _, arg := range args {
		for _, value := range values {
			if arg == value {
				return true
			}
		}
	}
	return false
}

func containsArgPrefix(args []string, prefixes ...string) bool {
	for _, arg := range args {
		for _, prefix := range prefixes {
			if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
				return true
			}
		}
	}
	return false
}

func isIPMutation(args []string) bool {
	objects := map[string]struct{}{
		"addr": {}, "address": {}, "link": {}, "route": {},
	}
	readOnlyOps := map[string]struct{}{
		"show": {}, "list": {}, "get": {}, "help": {}, "save": {}, "monitor": {},
	}
	for i, arg := range args {
		if _, ok := objects[arg]; !ok {
			continue
		}
		for _, op := range args[i+1:] {
			if strings.HasPrefix(op, "-") {
				continue
			}
			if _, ok := readOnlyOps[op]; ok {
				return false
			}
			return true
		}
		return false
	}
	return false
}

func isDatabaseMutation(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if _, ok := databaseClients[filepath.Base(strings.ToLower(args[0]))]; !ok {
		return false
	}
	for _, arg := range args[1:] {
		if databaseMutationPattern.MatchString(arg) {
			return true
		}
	}
	return false
}
