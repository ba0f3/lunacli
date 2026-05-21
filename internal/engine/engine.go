package engine

import (
	"fmt"
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
	pol *policy.Policy
}

func NewEngine(pol *policy.Policy) *Engine {
	return &Engine{pol: pol}
}

func (e *Engine) Classify(command string, host string, tags []string) Result {
	cmd := strings.TrimSpace(command)
	if len(cmd) > maxCommandLen {
		return Result{Class: Forbidden, Reason: "command exceeds maximum length"}
	}

	for _, re := range forbiddenPatterns {
		if re.MatchString(cmd) {
			return Result{Class: Forbidden, Reason: "command matches compiled forbidden pattern"}
		}
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
				flag(Mutating, "command contains output redirection")
			}
		case *syntax.CmdSubst, *syntax.ProcSubst:
			flag(Mutating, "command contains substitution")
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

			for _, re := range forbiddenPatterns {
				if re.MatchString(unquotedCmd) {
					flag(Forbidden, "command matches compiled forbidden pattern")
					return false
				}
			}

			for _, re := range mutatingFlagPatterns {
				if re.MatchString(lowerCmd) {
					flag(Mutating, "command contains mutating flags")
					return true
				}
			}

			if isDatabaseMutation(args) {
				flag(Mutating, "database mutation statement")
				return true
			}

			if e.pol != nil {
				for _, pat := range e.pol.DenyPatterns {
					if matched, _ := regexp.MatchString(pat, cmd); matched {
						flag(Forbidden, fmt.Sprintf("command matches policy deny pattern: %q", pat))
						return false
					}
				}

				matched := false
				for _, rule := range e.pol.Rules {
					if !matchHostOrTags(rule.Hosts, rule.Tags, host, tags) {
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
