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
