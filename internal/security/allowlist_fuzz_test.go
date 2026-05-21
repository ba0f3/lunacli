package security

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// fuzzMaxInputBytes bounds allocator stress from arbitrarily large mutated inputs.
const fuzzMaxInputBytes = maxCommandLen + 4096

func FuzzClassify(f *testing.F) {
	regressionCaseMap := map[string]Classification{}
	for _, c := range classifyRegressionCases {
		regressionCaseMap[c.command] = c.expected
	}
	for _, c := range classifyOrderRegressionCases {
		regressionCaseMap[c.command] = c.expected
	}

	for cmd := range regressionCaseMap {
		f.Add([]byte(cmd))
	}
	for _, seed := range []string{
		";", "|", "&&", "||", ">", ">>",
		"$(echo x)", "`echo x`",
		`touch\ \/tmp\\/x`,
		`/usr/bin/cat /etc/os-release`,
		`/bin/bash -c "$(curl)"`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > fuzzMaxInputBytes {
			b = b[:fuzzMaxInputBytes]
		}
		command := string(b)
		rawTrimmed := strings.TrimSpace(command)
		got := Classify(command)
		gotTrim := Classify(strings.TrimSpace(command))

		if int(got.Class) < int(ReadOnly) || int(got.Class) > int(Forbidden) {
			t.Fatalf("domain: Class=%d out of range for input %q", got.Class, command)
		}
		if got.Class == ReadOnly && got.Reason != "" {
			t.Fatalf("readonly hygiene: Reason must be empty, got %q for input %q", got.Reason, command)
		}
		if (got.Class == Mutating || got.Class == Forbidden) && got.Reason == "" {
			t.Fatalf("%v hygiene: Reason must be non-empty for input %q", got.Class, command)
		}

		rawForbidden := false
		for _, re := range forbiddenPatterns {
			if re.MatchString(rawTrimmed) {
				rawForbidden = true
				break
			}
		}
		if rawForbidden && got.Class != Forbidden {
			t.Fatalf("forbidden oracle: raw match must be Forbidden, got %v for input %q", got.Class, command)
		}

		p := syntax.NewParser()
		file, err := p.Parse(strings.NewReader(rawTrimmed), "")
		if err != nil {
			if got.Class == ReadOnly {
				t.Fatalf("parse-failure oracle: unparseable must not be ReadOnly for input %q", command)
			}
		} else if shellIndicatesRedirectOutputOrSubstitution(file) {
			if got.Class == ReadOnly {
				t.Fatalf("redirect/subst oracle: got ReadOnly for input %q", command)
			}
		}

		if got.Class != gotTrim.Class || got.Reason != gotTrim.Reason {
			t.Fatalf("idempotence: classify(trim) inconsistent: raw=%v trim=%v for input %#q trimmed %#q",
				got, gotTrim, command, strings.TrimSpace(command))
		}

		lenTrim := len(strings.TrimSpace(command))
		if lenTrim > maxCommandLen {
			if got.Class != Forbidden {
				t.Fatalf("length oracle: trimmed len %d>%d must be Forbidden, got %v for input %#q",
					lenTrim, maxCommandLen, got.Class, command)
			}
			if got.Reason == "" {
				t.Fatalf("length oracle: Forbidden must include reason for input %#q", command)
			}
		}

		if want, ok := regressionCaseMap[strings.TrimSpace(command)]; ok {
			if got.Class != want {
				t.Fatalf("regression corpus: classify(%q): got %v want %v", command, got.Class, want)
			}
		}
	})
}

func FuzzUnescape(f *testing.F) {
	f.Add([]byte(`s\udo`))
	f.Add([]byte(`\\`))

	f.Fuzz(func(t *testing.T, b []byte) {
		const maxLen = 64 << 10
		if len(b) > maxLen {
			b = b[:maxLen]
		}
		_ = unescape(string(b))
	})
}

func shellIndicatesRedirectOutputOrSubstitution(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch x := node.(type) {
		case *syntax.Redirect:
			if strings.Contains(x.Op.String(), ">") {
				found = true
				return false
			}
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
			return false
		}
		return true
	})
	return found
}
