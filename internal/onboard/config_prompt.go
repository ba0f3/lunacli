package onboard

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

func showExistingConfig(out io.Writer, path string, fs config.FileSettings) error {
	if err := writef(out, "Existing config: %s\n", path); err != nil {
		return err
	}
	if fs.ConfigDir != "" {
		if err := writef(out, "  config_dir: %s\n", fs.ConfigDir); err != nil {
			return err
		}
	}
	if fs.Approval.TTL != "" {
		if err := writef(out, "  approval.ttl: %s\n", fs.Approval.TTL); err != nil {
			return err
		}
	}
	mode := fs.Transport.Mode
	if mode == "" {
		mode = "proxy (default)"
	}
	if err := writef(out, "  transport.mode: %s\n", mode); err != nil {
		return err
	}
	endpoint := fs.Transport.Proxy.Endpoint
	if endpoint == "" {
		endpoint = "(not set)"
	}
	if err := writef(out, "  transport.proxy.endpoint: %s\n", endpoint); err != nil {
		return err
	}
	if fs.Telegram.BotTokenFile != "" {
		if err := writef(out, "  telegram.bot_token_file: %s\n", fs.Telegram.BotTokenFile); err != nil {
			return err
		}
	}
	if fs.Telegram.ApproverUserID != "" {
		if err := writef(out, "  telegram.approver_user_id: %s\n", fs.Telegram.ApproverUserID); err != nil {
			return err
		}
	}
	if fs.Telegram.ChatID != "" {
		if err := writef(out, "  telegram.chat_id: %s\n", fs.Telegram.ChatID); err != nil {
			return err
		}
	}
	return writeBlank(out)
}

func transportConfigured(fs config.TransportSettings) bool {
	mode := fs.Mode
	if mode == "" {
		mode = "proxy"
	}
	switch mode {
	case "direct", "luna-agent":
		return true
	case "proxy":
		return strings.TrimSpace(fs.Proxy.Endpoint) != ""
	default:
		return false
	}
}

func telegramConfigured(fs config.TelegramSettings) bool {
	return strings.TrimSpace(fs.ApproverUserID) != "" &&
		strings.TrimSpace(fs.ChatID) != "" &&
		botTokenFileUsable(fs.BotTokenFile)
}

func botTokenFileUsable(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	token, err := ReadBotToken(path)
	return err == nil && token != ""
}

func configComplete(fs config.FileSettings) bool {
	return transportConfigured(fs.Transport) && telegramConfigured(fs.Telegram)
}

func promptKeepOrUpdate(p *Prompter, section string) (keep bool, err error) {
	idx, err := p.Choice(section, []string{
		"Keep current settings",
		"Update settings",
	}, 0)
	if err != nil {
		return false, err
	}
	return idx == 0, nil
}

func displayTransportMode(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "proxy (default)"
	}
	return mode
}

func mergeApproval(existing config.ApprovalSettings, ly Layout) config.ApprovalSettings {
	if existing.TTL != "" {
		return existing
	}
	return config.ApprovalSettings{TTL: "10m"}
}

func mergeConfigDir(existing string, ly Layout) string {
	if existing != "" {
		return existing
	}
	return ly.ConfigDirRel
}

func formatKeepSkip(label string) string {
	return fmt.Sprintf("%s [Enter to keep]: ", label)
}
