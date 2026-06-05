package security

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Classification describes whether a command is safe, requires approval, or is forbidden.
type Classification int

const (
	// ReadOnly commands never modify system state. Always permitted.
	ReadOnly Classification = iota
	// Mutating commands change system state. Require allow_mutations=true.
	Mutating
	// Forbidden commands are never permitted regardless of flags.
	Forbidden
)

func (c Classification) String() string {
	switch c {
	case ReadOnly:
		return "read-only"
	case Mutating:
		return "mutating"
	case Forbidden:
		return "forbidden"
	default:
		return "unknown"
	}
}

// CheckResult is the output of Classify.
type CheckResult struct {
	Class  Classification
	Reason string // human-readable explanation returned to the LLM
}

// maxCommandLen is the maximum allowed command length in characters.
// Commands exceeding this are rejected to prevent obfuscation and DoS.
const maxCommandLen = 4096

// forbiddenPatterns matches commands that are unconditionally blocked.
// These are catastrophic or irreversible operations.
var forbiddenPatterns = []*regexp.Regexp{
	// Recursive forced deletion of root-level paths
	regexp.MustCompile(`(?i)\brm\s+(?:-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*|-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+/(?:\s+|$)`),
	// Disk/filesystem destruction
	regexp.MustCompile(`(?i)\bmkfs\b`),                // mkfs.*
	regexp.MustCompile(`(?i)\bdd\s+if=`),              // dd if=...
	regexp.MustCompile(`(?i)>\s*/dev/sd[a-z]`),        // > /dev/sda
	regexp.MustCompile(`(?i)>\s*/dev/nvme`),           // > /dev/nvme
	regexp.MustCompile(`(?i)>\s*/dev/hd[a-z]`),        // > /dev/hda (old disks)
	regexp.MustCompile(`(?i)>\s*/dev/mapper/`),        // > /dev/mapper/ (LVM)
	regexp.MustCompile(`(?i)\bshred\b`),               // shred
	regexp.MustCompile(`(?i)\bwipefs\b`),              // wipefs
	regexp.MustCompile(`(?i)\bfdisk\b`),               // fdisk
	regexp.MustCompile(`(?i)\bparted\b`),              // parted
	regexp.MustCompile(`(?i)\bcrypt\w*\s+luksFormat`), // cryptsetup luksFormat
	regexp.MustCompile(`(?i)\bdebugfs\b`),             // debugfs (ext filesystem editor)
	regexp.MustCompile(`(?i)\btune2fs\b`),             // tune2fs (filesystem parameter changes)
	regexp.MustCompile(`(?i)\bresize2fs\b`),           // resize2fs
	regexp.MustCompile(`(?i)\bxfs_growfs\b`),          // xfs_growfs
	regexp.MustCompile(`(?i)\bfsck\b`),                // fsck (filesystem check/repair)
	regexp.MustCompile(`(?i)\bbadblocks\b`),           // badblocks (destructive write test)
	regexp.MustCompile(`(?i)\bhdparm\b`),              // hdparm (dangerous disk parameters)
	// Fork bomb
	regexp.MustCompile(`(?i):\(\)\s*\{`),
	// Firewall flush (locks everyone out)
	regexp.MustCompile(`(?i)\biptables\s+-F\b`), // iptables -F (flush all rules)
	regexp.MustCompile(`(?i)\bnft\s+flush\b`),   // nft flush
	// Privilege escalation / credential modification
	regexp.MustCompile(`(?i)(?:^|[|&;])passwd\b`),                         // passwd
	regexp.MustCompile(`(?i)(?:^|[|&;])(?:useradd|userdel|usermod)\b`),    // user management
	regexp.MustCompile(`(?i)(?:^|[|&;])(?:groupadd|groupdel|groupmod)\b`), // group management
	regexp.MustCompile(`(?i)(?:^|[|&;])visudo\b`),                         // sudoers edit
	regexp.MustCompile(`(?i)(?:^|[|&;])sudo\b`),                           // sudo (privilege escalation)
	regexp.MustCompile(`(?i)(?:^|[|&;])su\b`),                             // su (switch user)
	regexp.MustCompile(`(?i)(?:^|[|&;])doas\b`),                           // doas (OpenBSD privilege escalation)
	// Kernel module manipulation
	regexp.MustCompile(`(?i)(?:^|[|&;])insmod\b`),   // insmod (load kernel module)
	regexp.MustCompile(`(?i)(?:^|[|&;])modprobe\b`), // modprobe (load kernel module)
	regexp.MustCompile(`(?i)(?:^|[|&;])rmmod\b`),    // rmmod (remove kernel module)
	// Reverse shell / network backdoor patterns
	regexp.MustCompile(`(?i)\bnc\s+.*-[el]`),                               // nc with -e/-l (reverse shell / listener)
	regexp.MustCompile(`(?i)\bncat\s+.*-[el]`),                             // ncat with -e/-l
	regexp.MustCompile(`(?i)\bsocat\b`),                                    // socat (arbitrary bidirectional streams)
	regexp.MustCompile(`(?i)/dev/tcp/`),                                    // bash /dev/tcp backdoor
	regexp.MustCompile(`(?i)/dev/udp/`),                                    // bash /dev/udp backdoor
	regexp.MustCompile(`(?i)\bbash\s+-i\b`),                                // bash interactive (common in reverse shells)
	regexp.MustCompile(`(?i)\bpython[23]?\s+.*-[ci]\b`),                    // python -c / python -i (code execution)
	regexp.MustCompile(`(?i)\bperl\s+(?:.*?\s)?-[a-z]*[ei][^\s]*(?:\s|$)`), // perl -e / perl -i (code execution)
	regexp.MustCompile(`(?i)\bruby\s+.*-[ei]\b`),                           // ruby -e / ruby -i (code execution)
	regexp.MustCompile(`(?i)\bnode\s+.*-[ei]\b`),                           // node -e / node -i (code execution)
	regexp.MustCompile(`(?i)\blua\b`),                                      // lua interpreter (code execution)
	// Script file execution (to prevent running uploaded scripts)
	regexp.MustCompile(`(?i)^python[23]?\s+\S`),
	regexp.MustCompile(`(?i)^ruby\s+\S`),
	regexp.MustCompile(`(?i)^node\s+\S`),
	regexp.MustCompile(`(?i)^perl\s+\S`),
	regexp.MustCompile(`(?i)^php\s+\S`),
	regexp.MustCompile(`(?i)^Rscript\s+\S`),
	regexp.MustCompile(`(?i)^(?:bash|sh|dash|zsh|ksh|csh|tcsh)\s+\S`),
	regexp.MustCompile(`(?i)^exec\s+\S`),
	// find with destructive actions
	regexp.MustCompile(`(?i)\bfind\s+.*-delete\b`),    // find -delete (recursive deletion)
	regexp.MustCompile(`(?i)\bfind\s+.*-exec\s+rm\b`), // find -exec rm (recursive deletion)
	// chmod 777 on critical paths
	regexp.MustCompile(`(?i)\bchmod\s+(?:[0-7]*777|[0-7]*777[0-7]*)\s+/(?:etc|bin|sbin|usr)\b`),
	// Writing to system-critical paths via tee
	regexp.MustCompile(`(?i)\btee\s+/(?:etc/passwd|etc/shadow|etc/sudoers|etc/ssh)\b`),
}

// readOnlyPrefixes are command prefixes that are always safe.
// IMPORTANT: These are sorted by length descending before matching so that
// longer, more-specific prefixes take priority (e.g. "sed -i" before "sed ").
var readOnlyPrefixes = []string{
	"systemctl status",
	"systemctl list-units",
	"systemctl is-active",
	"systemctl is-enabled",
	"systemctl cat",
	"journalctl",
	"cat ",
	"ls",
	"ps",
	"top -b",
	"htop",
	"df",
	"free",
	"ss",
	"ip addr",
	"ip link",
	"ip route",
	"ip neigh",
	"ping ",
	"traceroute ",
	"tracepath ",
	"mtr ",
	"nslookup ",
	"dig ",
	"host ",
	"uname",
	"uptime",
	"who",
	"w",
	"last",
	"id",
	"whoami",
	"hostname",
	"date",
	"locate ",
	"which ",
	"whereis ",
	"stat ",
	"file ",
	"head ",
	"tail ",
	"less ",
	"more ",
	"grep ",
	"egrep ",
	"fgrep ",
	"awk ", // awk without -i is read-only; "awk -i" is in mutatingPrefixes
	"sed ", // sed without -i is read-only; "sed -i" is in mutatingPrefixes
	"sort ",
	"uniq ",
	"wc ",
	"cut ",
	"tr ",
	"diff ",
	"md5sum ",
	"sha256sum ",
	"lsof ",
	"netstat ",
	"ifconfig",
	"route ",
	"arp ",
	"dmesg",
	"sysctl -a",
	"printenv",
	"echo ",
	"docker ps",
	"docker images",
	"docker logs",
	"docker inspect",
	"docker stats",
	"docker network ls",
	"docker volume ls",
	"docker version",
	"docker info",
	"docker diff", // shows filesystem changes (read-only)
	"docker port", // shows port mappings (read-only)
	"docker top",  // shows processes in container (read-only)
	"kubectl get",
	"kubectl describe",
	"kubectl logs",
	"kubectl top",
	"kubectl explain",
	"kubectl version",
	"kubectl cluster-info",
	"kubectl auth can-i", // check RBAC permissions (read-only)
	"kubectl api-resources",
	"kubectl api-versions",
	"timedatectl",
	"hostnamectl",
	"localectl",
	"lsblk",
	"lspci",
	"lsusb",
	"lscpu",
	"lsmem",
	"dmidecode",
	"smartctl",
	"iostat",
	"vmstat",
	"sar ",
	"mpstat",
	"pidstat",
	"strace -p", // strace with -p (attach to PID) is read-only observation
	"ltrace -p",
	"rpm -q",
	"dpkg -l",
	"dpkg -s",
	"apt-cache",
	"yum info",
	"yum list",
	"dnf info",
	"dnf list",
	"snap list",
	"flatpak list",
	"git log",
	"git status",
	"git diff",
	"git show",
	"git branch",
	"git remote",
	"crontab -l",
	"at -l",
	"iptables -L",
	"iptables -S",
	"find ", // find without -delete/-exec is read-only; destructive variants are in forbiddenPatterns
	"nmap ", // basic scan only; aggressive modes should be reviewed
}

// mutatingPrefixes are command prefixes that change system state.
// Permitted only when allow_mutations=true.
// IMPORTANT: These are sorted by length descending before matching so that
// longer, more-specific prefixes take priority (e.g. "sed -i" before "sed ").
var mutatingPrefixes = []string{
	"systemctl start",
	"systemctl stop",
	"systemctl restart",
	"systemctl reload",
	"systemctl enable",
	"systemctl disable",
	"systemctl mask",
	"systemctl unmask",
	"systemctl edit",
	"service ",
	"apt-get install",
	"apt-get remove",
	"apt-get purge",
	"apt-get upgrade",
	"apt install",
	"apt remove",
	"apt purge",
	"apt upgrade",
	"apt update",
	"yum install",
	"yum remove",
	"yum update",
	"yum upgrade",
	"dnf install",
	"dnf remove",
	"dnf update",
	"dnf upgrade",
	"pip install",
	"pip uninstall",
	"npm install",
	"npm uninstall",
	"cp ",
	"mv ",
	"mkdir ",
	"rmdir ",
	"touch ",
	"chmod ",
	"chown ",
	"chgrp ",
	"ln ",
	"tee ",
	"truncate ",
	"rm ",
	"docker start",
	"docker stop",
	"docker restart",
	"docker rm",
	"docker rmi",
	"docker pull",
	"docker run",
	"docker exec",
	"docker build",
	"docker cp", // copy files in/out of container (data exfil/mutation)
	"docker-compose",
	"kubectl apply",
	"kubectl delete",
	"kubectl scale",
	"kubectl rollout",
	"kubectl patch",
	"kubectl edit",
	"kubectl cordon",
	"kubectl drain",
	"kubectl uncordon",
	"kubectl taint",
	"kubectl label",
	"kubectl annotate",
	"kubectl cp", // copy files in/out of pod (data exfil/mutation)
	"iptables -A",
	"iptables -D",
	"iptables -I",
	"iptables -R",
	"ufw allow",
	"ufw deny",
	"ufw enable",
	"ufw disable",
	"ufw delete",
	"firewall-cmd",
	"sysctl -w",
	"sysctl -p", // loads values from file — can be mutating
	"ulimit ",
	"crontab ",
	"at ",
	"reboot",
	"shutdown",
	"halt",
	"poweroff",
	"kill ",
	"killall ",
	"pkill ",
	"nice ",
	"renice ",
	"mount ",
	"umount ",
	"chattr ",  // change file attributes (immutable flag etc.)
	"lsattr ",  // technically read-only but listed for completeness
	"setfacl ", // modify ACLs
	"tar ",     // extraction overwrites files
	"unzip ",   // extraction overwrites files
	"rsync ",   // can delete/overwrite remote files
	"scp ",     // file transfer (data exfil/mutation)
	"sftp ",    // file transfer (data exfil/mutation)
}

// mutatingFlagPatterns matches command+flag combinations that are mutating
// even though the base command might be read-only.
// Each pattern is checked against the full command string.
var mutatingFlagPatterns = []*regexp.Regexp{
	// curl with data upload or local file write flags
	regexp.MustCompile(`(?i)\bcurl\s+.*(?:-[A-Za-z]*d|--data|--data-binary|--data-raw|--data-urlencode|--post-file|-T\s|--upload-file)\b`),
	regexp.MustCompile(`(?i)\bcurl\s+.*(?:-o\s|--output|-O)\b`),
	// wget with post/upload or output file flags
	regexp.MustCompile(`(?i)\bwget\s+.*(?:--post-data|--post-file|--body-data|--body-file|-O\s|--output-document)\b`),
	// find with -exec or -ok (arbitrary command execution)
	regexp.MustCompile(`(?i)\bfind\s+.*-(?:exec|ok)\b`),
	// sed with in-place editing flag
	regexp.MustCompile(`(?i)\bsed\s+(?:.*?\s)?(?:-[a-z]*i[^\s]*|--in-place)(?:\s|$)`),
	// awk with in-place editing flag
	regexp.MustCompile(`(?i)\bawk\s+(?:.*?\s)?-[a-z]*i[^\s]*(?:\s|$)`),
}

var databaseClients = map[string]struct{}{
	"clickhouse-client": {},
	"duckdb":            {},
	"mariadb":           {},
	"mongo":             {},
	"mongosh":           {},
	"mysql":             {},
	"psql":              {},
	"sqlite":            {},
	"sqlite3":           {},
}

var databaseMutationPattern = regexp.MustCompile(`(?i)\b(?:update|delete\s+from|drop|create)\b`)

type commandPrefix struct {
	exact  string
	prefix string
}

var preparedReadOnlyPrefixesMap map[string][]commandPrefix
var preparedMutatingPrefixesMap map[string][]commandPrefix

// init sorts prefix lists by length descending so that longer, more-specific
// prefixes are checked before shorter ones. This prevents "sed " from matching
// before "sed -i", etc. It also precomputes trimmed and lowercased variants
// and groups them by the first word to allow O(1) lookups in Classify.
func init() {
	sortByLengthDesc(readOnlyPrefixes)
	sortByLengthDesc(mutatingPrefixes)

	preparedReadOnlyPrefixesMap = preparePrefixes(readOnlyPrefixes)
	preparedMutatingPrefixesMap = preparePrefixes(mutatingPrefixes)
}

func preparePrefixes(list []string) map[string][]commandPrefix {
	// ⚡ Bolt Optimization: Build a map indexed by the first word of the command
	// to avoid O(N) linear scanning of all prefixes during Classify.
	res := make(map[string][]commandPrefix)
	for _, p := range list {
		clean := strings.TrimRight(strings.ToLower(p), " \n")
		cp := commandPrefix{
			exact:  clean,
			prefix: clean + " ",
		}

		idx := strings.IndexByte(clean, ' ')
		firstWord := clean
		if idx >= 0 {
			firstWord = clean[:idx]
		}

		res[firstWord] = append(res[firstWord], cp)
	}
	return res
}

func sortByLengthDesc(list []string) {
	sort.Slice(list, func(i, j int) bool {
		return len(list[i]) > len(list[j])
	})
}

// unescape removes backslash escapes from a string (e.g. "s\\udo" -> "sudo")
// to prevent attackers from bypassing the allowlist by escaping characters.
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

// unwrapCommand skips over wrapper commands like "env" and "xargs" to find
// the actual executable being invoked. It handles wrapper options and
// environment variable assignments.
// Returns the updated args slice with the wrapper tokens removed.
func unwrapCommand(args []string) []string {
	if len(args) == 0 {
		return args
	}

	for {
		if len(args) == 0 {
			return args
		}

		cmd := args[0]

		// Handle "env" wrapper
		if cmd == "env" {
			// Skip past env and any options/assignments
			i := 1
			for i < len(args) {
				arg := args[i]
				// Skip environment variable assignments (KEY=VALUE)
				if strings.Contains(arg, "=") {
					i++
					continue
				}
				// Skip flags (starting with -)
				if strings.HasPrefix(arg, "-") {
					i++
					// Some flags take arguments, but for simplicity we'll just skip the flag
					// The next iteration will handle whether the next token is also a flag/assignment
					continue
				}
				// First non-option/non-assignment token is the real command
				break
			}
			if i >= len(args) {
				// No actual command after env
				return args
			}
			// Remove the wrapper tokens
			args = args[i:]
			continue
		}

		// Handle "xargs" wrapper
		if cmd == "xargs" {
			// Skip past xargs and any options
			i := 1
			for i < len(args) {
				arg := args[i]
				// Skip flags (starting with -)
				if strings.HasPrefix(arg, "-") {
					i++
					continue
				}
				// First non-option token is the real command
				break
			}
			if i >= len(args) {
				// No actual command after xargs
				return args
			}
			// Remove the wrapper tokens
			args = args[i:]
			continue
		}

		// Not a wrapper, we're done
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

func Classify(command string) CheckResult {
	cmd := strings.TrimSpace(command)

	// 0. Reject excessively long commands (obfuscation / DoS vector).
	if len(cmd) > maxCommandLen {
		return CheckResult{
			Class:  Forbidden,
			Reason: "command exceeds maximum allowed length (potential obfuscation or DoS attempt)",
		}
	}

	// 1. Check forbidden patterns first on RAW string (defense-in-depth).
	for _, re := range forbiddenPatterns {
		if re.MatchString(cmd) {
			return CheckResult{
				Class:  Forbidden,
				Reason: "command matches a permanently blocked pattern (catastrophic/irreversible operation)",
			}
		}
	}

	// 2. Parse the shell command securely.
	p := syntax.NewParser()
	file, err := p.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return CheckResult{
			Class:  Mutating,
			Reason: "command syntax could not be parsed securely — treated as mutating",
		}
	}

	resultClass := ReadOnly
	var resultReason string

	// Flagging helper
	flag := func(c Classification, reason string) {
		if c > resultClass {
			resultClass = c
			resultReason = reason
		}
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if resultClass == Forbidden {
			return false // stop walking if already forbidden
		}

		switch x := node.(type) {
		case *syntax.Redirect:
			op := x.Op.String()
			// > and >> and &> and >& modify files. < is read-only input.
			if strings.Contains(op, ">") {
				flag(Mutating, "command contains output redirection — re-run with allow_mutations=true after user approval")
			}
		case *syntax.CmdSubst, *syntax.ProcSubst:
			flag(Mutating, "command contains substitution — re-run with allow_mutations=true after user approval")
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}

			// Reconstruct unquoted command parts to defeat obfuscation (e.g. c'a't)
			var args []string
			for _, arg := range x.Args {
				isStatic := true
				var builder strings.Builder
				for _, part := range arg.Parts {
					switch p := part.(type) {
					case *syntax.Lit:
						builder.WriteString(unescape(p.Value))
					case *syntax.SglQuoted:
						builder.WriteString(p.Value)
					case *syntax.DblQuoted:
						for _, dp := range p.Parts {
							if dpl, ok := dp.(*syntax.Lit); ok {
								builder.WriteString(unescape(dpl.Value))
							} else {
								isStatic = false
							}
						}
					default:
						isStatic = false
					}
				}
				if isStatic {
					args = append(args, builder.String())
				} else {
					args = append(args, "<DYNAMIC>")
				}
			}

			// Base command must be statically verifiable
			if args[0] == "<DYNAMIC>" {
				flag(Mutating, "dynamic base command — treated as mutating by default")
				return true
			}

			// Strip directory path from the binary name (e.g. /usr/bin/rm -> rm)
			args[0] = filepath.Base(args[0])

			// Unwrap wrapper commands (env, xargs) to find the real executable
			args = unwrapCommand(args)
			if len(args) == 0 {
				flag(Mutating, "command appears to be only a wrapper with no actual command")
				return true
			}

			// Re-apply filepath.Base after unwrapping in case the unwrapped command has a path
			args[0] = filepath.Base(args[0])

			unquotedCmd := strings.Join(args, " ")
			lowerCmd := strings.ToLower(unquotedCmd)

			// Check forbidden on the unquoted, reconstructed string
			for _, re := range forbiddenPatterns {
				if re.MatchString(unquotedCmd) {
					flag(Forbidden, "command matches a permanently blocked pattern (catastrophic/irreversible operation)")
					return false
				}
			}

			// Check mutating flag patterns
			for _, re := range mutatingFlagPatterns {
				if re.MatchString(lowerCmd) {
					flag(Mutating, "command contains mutating flags — re-run with allow_mutations=true after user approval")
					return true
				}
			}

			if isDatabaseMutation(args) {
				flag(Mutating, "database mutation statement detected — re-run with allow_mutations=true after user approval")
				return true
			}

			// Extract the first word of the lowercased command to perform fast O(1) map lookups.
			idx := strings.IndexByte(lowerCmd, ' ')
			firstWord := lowerCmd
			if idx >= 0 {
				firstWord = lowerCmd[:idx]
			}

			// Check mutating prefixes
			// ⚡ Bolt Optimization: Look up prefixes by the first word of the command
			// to reduce O(N) iteration over all mutating prefixes to O(1) + minor iteration.
			matchedMutating := false
			if cps, ok := preparedMutatingPrefixesMap[firstWord]; ok {
				for _, cp := range cps {
					if lowerCmd == cp.exact || strings.HasPrefix(lowerCmd, cp.prefix) {
						flag(Mutating, "command modifies system state — re-run with allow_mutations=true after user approval")
						matchedMutating = true
						break
					}
				}
			}
			if matchedMutating {
				return true
			}

			// Check read-only prefixes
			// ⚡ Bolt Optimization: Same map lookup optimization for read-only prefixes.
			matchedReadOnly := false
			if cps, ok := preparedReadOnlyPrefixesMap[firstWord]; ok {
				for _, cp := range cps {
					if lowerCmd == cp.exact || strings.HasPrefix(lowerCmd, cp.prefix) {
						matchedReadOnly = true
						break
					}
				}
			}

			if !matchedReadOnly {
				flag(Mutating, "unrecognised command — treated as mutating by default; re-run with allow_mutations=true after user approval")
			}
		}
		return true
	})

	return CheckResult{Class: resultClass, Reason: resultReason}
}
