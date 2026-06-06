package onboard

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type Prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func NewPrompter(in io.Reader, out io.Writer) *Prompter {
	return &Prompter{in: bufio.NewReader(in), out: out}
}

func (p *Prompter) Choice(prompt string, options []string, defaultIdx int) (int, error) {
	for i, o := range options {
		d := ""
		if i == defaultIdx {
			d = " [default]"
		}
		if err := writef(p.out, "  %d) %s%s\n", i+1, o, d); err != nil {
			return 0, err
		}
	}
	if err := writef(p.out, "%s [%d]: ", prompt, defaultIdx+1); err != nil {
		return 0, err
	}
	line, err := p.in.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultIdx, nil
	}
	var n int
	if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(options) {
		return defaultIdx, nil
	}
	return n - 1, nil
}

func (p *Prompter) Line(prompt string) (string, error) {
	if _, err := fmt.Fprint(p.out, prompt); err != nil {
		return "", err
	}
	line, err := p.in.ReadString('\n')
	return strings.TrimSpace(line), err
}

// LineOrKeep prompts for a value; empty input keeps current when current is set.
func (p *Prompter) LineOrKeep(label, current string) (string, error) {
	if strings.TrimSpace(current) != "" {
		if err := writef(p.out, "  current: %s\n", current); err != nil {
			return "", err
		}
		val, err := p.Line(formatKeepSkip(label))
		if err != nil {
			return "", err
		}
		if val == "" {
			return current, nil
		}
		return val, nil
	}
	val, err := p.Line(label + ": ")
	if err != nil {
		return "", err
	}
	return val, nil
}
