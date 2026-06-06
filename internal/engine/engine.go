package engine

import (
	"fmt"
	"net"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ba0f3/lunacli/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

type Classification string

const (
	ReadOnly  Classification = "read-only"
	Mutating  Classification = "mutating"
	Forbidden Classification = "forbidden"
)

type Result struct {
	Class  Classification
	Reason string
}

type Engine struct {
	pol                  *policy.Policy
	compiledDenyPatterns []*regexp.Regexp
}

func NewEngine(pol *policy.Policy) *Engine {
	// ⚡ Bolt Optimization: Pre-compile custom deny patterns once during initialization
	// to avoid expensive recompilation on every Classify call.
	var compiledDenyPatterns []*regexp.Regexp
	if pol != nil {
		for _, pat := range pol.DenyPatterns {
			if re, err := regexp.Compile(pat); err == nil {
				compiledDenyPatterns = append(compiledDenyPatterns, re)
			}
		}
	}
	return &Engine{
		pol:                  pol,
		compiledDenyPatterns: compiledDenyPatterns,
	}
}

func (e *Engine) Classify(command string, host string, tags []string) Result {
	return e.ClassifyTargets(command, []string{host}, tags)
}

// ClassifyTargets evaluates policy against every identity for the same target,
// such as the caller's SSH alias and the canonical approved endpoint.
func (e *Engine) ClassifyTargets(command string, hosts []string, tags []string) Result {
	cmd := strings.TrimSpace(command)
	if len(cmd) > maxCommandLen {
		return Result{Class: Forbidden, Reason: "command exceeds maximum length"}
	}

	p := syntax.NewParser()
	file, err := p.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return Result{Class: Mutating, Reason: "syntax error, treated as mutating by default"}
	}

	var res Result
	res.Class = ReadOnly

	flag := func(c Classification, reason string) {
		if c == Forbidden {
			res.Class = Forbidden
			res.Reason = reason
		} else if c == Mutating && res.Class != Forbidden {
			res.Class = Mutating
			res.Reason = reason
		}
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		if res.Class == Forbidden {
			return false
		}
		switch x := node.(type) {
		case *syntax.Redirect:
			if strings.Contains(x.Op.String(), ">") {
				target, ok := wordStaticString(x.Word)
				if ok && isForbiddenRedirectTarget(target) {
					flag(Forbidden, "command redirects output to a block device")
				} else if !ok || !isSafeOutputRedirect(x.Op.String(), target) {
					flag(Mutating, "command contains output redirection")
				}
			}
		case *syntax.CmdSubst, *syntax.ProcSubst:
			flag(Mutating, "command contains substitution")
		case *syntax.FuncDecl:
			if x.Name != nil && x.Name.Value == ":" {
				flag(Forbidden, "command declares fork-bomb function")
			}
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}
			var args []string
			for _, arg := range x.Args {
				var b strings.Builder
				isStatic := true
				for _, part := range arg.Parts {
					switch p := part.(type) {
					case *syntax.Lit:
						b.WriteString(unescape(p.Value))
					case *syntax.SglQuoted:
						b.WriteString(p.Value)
					case *syntax.DblQuoted:
						for _, dp := range p.Parts {
							if dpl, ok := dp.(*syntax.Lit); ok {
								b.WriteString(unescape(dpl.Value))
							} else {
								isStatic = false
							}
						}
					default:
						isStatic = false
					}
				}
				if isStatic {
					args = append(args, b.String())
				} else {
					args = append(args, "<DYNAMIC>")
				}
			}

			if args[0] == "<DYNAMIC>" {
				flag(Mutating, "dynamic command")
				return true
			}

			args[0] = filepath.Base(args[0])
			args = unwrapCommand(args)
			if len(args) == 0 {
				flag(Mutating, "empty wrapped command")
				return true
			}
			args[0] = filepath.Base(args[0])
			unquotedCmd := strings.Join(args, " ")
			lowerCmd := strings.ToLower(unquotedCmd)

			if !isLiteralInspectionCommand(args[0]) {
				for _, re := range forbiddenPatterns {
					if re.MatchString(unquotedCmd) {
						flag(Forbidden, "command matches compiled forbidden pattern")
						return false
					}
				}
			}

			if hasMutatingFlagPatterns(args[0]) {
				for _, re := range mutatingFlagPatterns {
					if re.MatchString(lowerCmd) {
						flag(Mutating, "command contains mutating flags")
						return true
					}
				}
			}

			if isSemanticMutation(args) {
				flag(Mutating, "command performs a mutating operation")
			}

			if isDatabaseMutation(args) {
				flag(Mutating, "database mutation statement")
				return true
			}

			if e.pol != nil {
				for _, re := range e.compiledDenyPatterns {
					if re.MatchString(cmd) {
						flag(Forbidden, fmt.Sprintf("command matches policy deny pattern: %q", re.String()))
						return false
					}
				}

				matched := false
				for _, rule := range e.pol.Rules {
					if !matchAnyHostOrTags(rule.Hosts, rule.Tags, hosts, tags) {
						continue
					}
					for _, rcmd := range rule.Commands {
						if rcmd.Binary == args[0] {
							if len(rcmd.ArgsPrefix) == 0 {
								matched = true
								actionClass := parseAction(rule.Action)
								flag(actionClass, fmt.Sprintf("matches rule with action %s", rule.Action))
								break
							}
							if matchesArgsPrefix(args[1:], rcmd.ArgsPrefix) {
								matched = true
								actionClass := parseAction(rule.Action)
								flag(actionClass, fmt.Sprintf("matches rule with action %s and args", rule.Action))
								break
							}
						}
					}
					if matched {
						break
					}
				}
				if !matched {
					flag(Mutating, "unrecognized command (deny-by-default)")
				}
			} else {
				flag(Mutating, "no policy configured, denying command")
			}
		}
		return true
	})

	return res
}

func matchAnyHostOrTags(ruleHosts, ruleTags, targetHosts, targetTags []string) bool {
	for _, targetHost := range targetHosts {
		for _, variant := range hostIdentityVariants(targetHost) {
			if matchHostOrTags(ruleHosts, ruleTags, variant, targetTags) {
				return true
			}
		}
	}
	return false
}

func hostIdentityVariants(target string) []string {
	variants := []string{target}
	host := target
	user := ""
	if at := strings.LastIndex(host, "@"); at >= 0 {
		user = host[:at]
		host = host[at+1:]
		variants = append(variants, host)
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		variants = append(variants, parsedHost)
		if user != "" {
			variants = append(variants, user+"@"+parsedHost)
		}
	}
	return variants
}

func parseAction(action string) Classification {
	switch action {
	case "allow":
		return ReadOnly
	case "approve":
		return Mutating
	case "deny":
		return Forbidden
	default:
		return Mutating
	}
}

func matchHostOrTags(hosts, tags []string, targetHost string, targetTags []string) bool {
	hostMatch := false
	for _, h := range hosts {
		if h == "*" || h == targetHost {
			hostMatch = true
			break
		}
	}
	if !hostMatch {
		return false
	}
	if len(tags) == 0 {
		return true
	}
	for _, t := range tags {
		if t == "*" {
			return true
		}
		for _, tt := range targetTags {
			if t == tt {
				return true
			}
		}
	}
	return false
}

func matchesArgsPrefix(args, prefixes []string) bool {
	if len(args) < len(prefixes) {
		return false
	}
	for i, pref := range prefixes {
		if args[i] != pref {
			return false
		}
	}
	return true
}

// wordStaticString returns the redirect target when it is a static path (no globs/vars).
func wordStaticString(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	quoted := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(unescape(p.Value))
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
			quoted = true
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				if dpl, ok := dp.(*syntax.Lit); ok {
					b.WriteString(unescape(dpl.Value))
				} else {
					return "", false
				}
			}
			quoted = true
		default:
			return "", false
		}
	}
	if quoted {
		return b.String(), true
	}
	return strings.TrimSpace(b.String()), true
}

func isDiscardRedirectTarget(target string) bool {
	return path.Clean(target) == "/dev/null"
}

func isSafeOutputRedirect(op, target string) bool {
	clean := path.Clean(target)
	if isDiscardRedirectTarget(clean) {
		return true
	}
	if op == ">&" && (target == "1" || target == "2" || target == "-") {
		return true
	}
	switch clean {
	case "/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/fd/2", "/proc/self/fd/1", "/proc/self/fd/2":
		return true
	default:
		return false
	}
}

func isForbiddenRedirectTarget(target string) bool {
	clean := path.Clean(target)
	return strings.HasPrefix(clean, "/dev/sd") ||
		strings.HasPrefix(clean, "/dev/hd") ||
		strings.HasPrefix(clean, "/dev/nvme") ||
		strings.HasPrefix(clean, "/dev/mapper/") ||
		strings.HasPrefix(clean, "/dev/tcp/") ||
		strings.HasPrefix(clean, "/dev/udp/")
}
