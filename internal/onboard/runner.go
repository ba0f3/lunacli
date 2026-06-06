package onboard

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ba0f3/lunacli/internal/config"
	"golang.org/x/term"
)

// Run executes the interactive onboard wizard.
func Run(in io.Reader, out, errOut io.Writer) error {
	if !term.IsTerminal(int(in.(*os.File).Fd())) {
		return fmt.Errorf("onboard requires an interactive terminal")
	}

	p := NewPrompter(in, out)

	if err := writeln(out, "Luna onboard — interactive setup"); err != nil {
		return err
	}
	if err := writeln(out, "Creates luna.config.json, policy files, luna-proxy transport, and Telegram approval settings."); err != nil {
		return err
	}
	if err := writeln(out, "Docs: docs/oob-approval.md"); err != nil {
		return err
	}
	if err := writeBlank(out); err != nil {
		return err
	}

	targetIdx, err := p.Choice("Install location", []string{
		"User-wide (~/.config/luna/)",
		"Project-local (./luna.d in current directory)",
	}, 0)
	if err != nil {
		return err
	}
	target := TargetUserWide
	if targetIdx == 1 {
		target = TargetProjectLocal
	}

	modeIdx, err := p.Choice("If files already exist", []string{
		"Merge — skip existing files",
		"Replace all — overwrite existing files",
	}, 0)
	if err != nil {
		return err
	}
	mode := WriteMerge
	if modeIdx == 1 {
		mode = WriteReplace
	}

	ly, err := NewLayout(target)
	if err != nil {
		return fmt.Errorf("layout: %w", err)
	}

	existing, hasExisting, err := ReadConfigJSON(ly.ConfigJSON)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	allowKeep := mode == WriteMerge && hasExisting

	if allowKeep {
		if err := showExistingConfig(out, ly.ConfigJSON, existing); err != nil {
			return err
		}
		if configComplete(existing) {
			idx, err := p.Choice("Existing configuration", []string{
				"Keep entire existing configuration",
				"Review and update settings section by section",
			}, 0)
			if err != nil {
				return err
			}
			if idx == 0 {
				if err := printNextSteps(out, ly, existing.Transport); err != nil {
					return err
				}
				return nil
			}
		}
	}

	written, err := InstallBundle(mode, ly)
	if err != nil {
		return fmt.Errorf("install bundle: %w", err)
	}
	for _, name := range []string{"policy.yml", "hosts.yml"} {
		path := filepath.Join(ly.PolicyDir, name)
		if written[name] {
			if err := writef(out, "Wrote %s\n", path); err != nil {
				return err
			}
		} else {
			if err := writef(out, "Skipped (exists): %s\n", path); err != nil {
				return err
			}
		}
	}

	transport, err := PromptTransport(p, out, errOut, existing.Transport, allowKeep)
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	telegram, err := PromptTelegram(p, out, errOut, ly, existing.Telegram, allowKeep)
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}

	fs := config.FileSettings{
		ConfigDir: mergeConfigDir(existing.ConfigDir, ly),
		Approval:  mergeApproval(existing.Approval, ly),
		Transport: transport,
		Telegram:  telegram,
	}
	if ok, err := WriteConfigJSON(ly.ConfigJSON, mode, fs); err != nil {
		return fmt.Errorf("write config: %w", err)
	} else if ok {
		if err := writef(out, "Wrote %s\n", ly.ConfigJSON); err != nil {
			return err
		}
	}

	return printNextSteps(out, ly, transport)
}

func printNextSteps(out io.Writer, ly Layout, transport config.TransportSettings) error {
	exe, _ := os.Executable()
	if err := writeBlank(out); err != nil {
		return err
	}
	if err := writeln(out, "Next steps:"); err != nil {
		return err
	}
	if err := writef(out, "  • Edit %s with your SSH host aliases\n", filepath.Join(ly.PolicyDir, "hosts.yml")); err != nil {
		return err
	}
	mode := transport.Mode
	if mode == "" || mode == "proxy" {
		if err := writef(out, "  • Ensure mTLS client certs exist under ~/.config/luna/certs/ (enroll during onboard if needed)\n"); err != nil {
			return err
		}
	}
	if err := writef(out, "  • Run: %s serve\n", exe); err != nil {
		return err
	}
	if err := writef(out, "  • MCP client command: [%q, \"serve\"]\n", exe); err != nil {
		return err
	}
	return nil
}

func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
