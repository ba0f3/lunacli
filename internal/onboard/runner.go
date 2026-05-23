package onboard

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

// Run executes the interactive onboard wizard.
func Run(in io.Reader, out, errOut io.Writer) error {
	if !stdinIsTerminal() {
		return fmt.Errorf("onboard requires an interactive terminal")
	}

	p := NewPrompter(in, out)

	if err := writeln(out, "Luna onboard — interactive setup"); err != nil {
		return err
	}
	if err := writeln(out, "Creates luna.config.json, policy files, and Telegram approval settings."); err != nil {
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

	if err := writeln(errOut, "Enter your Telegram bot token (from @BotFather). Input may be visible — beware shoulder-surfing."); err != nil {
		return err
	}
	token, err := p.Line("Bot token: ")
	if err != nil {
		return err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("empty bot token")
	}
	if err := SaveBotToken(ly.TokenFile, token); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	if err := writef(out, "Saved bot token to %s\n", ly.TokenFile); err != nil {
		return err
	}

	if err := writeBlank(out); err != nil {
		return err
	}
	for _, line := range []string{
		"Telegram setup:",
		"  1. Open Telegram and find your bot",
		"  2. Send /start to the bot",
		"  3. Return here and press Enter",
	} {
		if err := writeln(out, line); err != nil {
			return err
		}
	}
	if _, err := p.Line("Press Enter when you have sent /start... "); err != nil {
		return err
	}

	ctx := context.Background()
	approverID, chatID, err := DiscoverApprover(ctx, token, nil, "")
	if err != nil {
		if err := writef(errOut, "Discovery failed: %v\n", err); err != nil {
			return err
		}
		if err := writeln(errOut, "Retrying once..."); err != nil {
			return err
		}
		approverID, chatID, err = DiscoverApprover(ctx, token, nil, "")
	}
	if err != nil {
		if err := writeln(errOut, "Could not detect your Telegram user id automatically."); err != nil {
			return err
		}
		if err := writeln(errOut, "Find your numeric id (e.g. message @userinfobot) and enter it below."); err != nil {
			return err
		}
		approverID, err = p.Line("Approver user id: ")
		if err != nil {
			return err
		}
		approverID = strings.TrimSpace(approverID)
		if approverID == "" {
			return fmt.Errorf("approver user id required")
		}
		chatID = approverID
	}

	fs := config.FileSettings{
		ConfigDir: ly.ConfigDirRel,
		Approval:  config.ApprovalSettings{TTL: "10m"},
		Telegram: config.TelegramSettings{
			BotTokenFile:     ly.TokenFile,
			ApproverUserID: approverID,
			ChatID:           chatID,
		},
	}
	if ok, err := WriteConfigJSON(ly.ConfigJSON, mode, fs); err != nil {
		return fmt.Errorf("write config: %w", err)
	} else if ok {
		if err := writef(out, "Wrote %s\n", ly.ConfigJSON); err != nil {
			return err
		}
	} else {
		if err := writef(out, "Skipped (exists): %s\n", ly.ConfigJSON); err != nil {
			return err
		}
	}

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
	if err := writef(out, "  • Run: %s serve\n", exe); err != nil {
		return err
	}
	if err := writef(out, "  • MCP client command: [%q, \"serve\"]\n", exe); err != nil {
		return err
	}
	return nil
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
