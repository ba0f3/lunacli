package onboard

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

func PromptTelegram(
	p *Prompter,
	out, errOut io.Writer,
	ly Layout,
	existing config.TelegramSettings,
	allowKeep bool,
) (config.TelegramSettings, error) {
	if allowKeep && telegramConfigured(existing) {
		if err := writeBlank(out); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writeln(out, "Telegram approval settings:"); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writef(out, "  current bot_token_file: %s\n", existing.BotTokenFile); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writef(out, "  current approver_user_id: %s\n", existing.ApproverUserID); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writef(out, "  current chat_id: %s\n", existing.ChatID); err != nil {
			return config.TelegramSettings{}, err
		}
		keep, err := promptKeepOrUpdate(p, "Telegram settings")
		if err != nil {
			return config.TelegramSettings{}, err
		}
		if keep {
			if err := writef(out, "Keeping Telegram settings.\n"); err != nil {
				return config.TelegramSettings{}, err
			}
			return existing, nil
		}
	}

	tokenPath := strings.TrimSpace(existing.BotTokenFile)
	if tokenPath == "" {
		tokenPath = ly.TokenFile
	}

	var token string
	if allowKeep && botTokenFileUsable(tokenPath) {
		if err := writef(out, "  current bot_token_file: %s\n", tokenPath); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writeln(errOut, "Enter a new bot token to replace the file, or press Enter to keep the existing token."); err != nil {
			return config.TelegramSettings{}, err
		}
		val, err := p.Line(formatKeepSkip("Bot token"))
		if err != nil {
			return config.TelegramSettings{}, err
		}
		if val == "" {
			token, err = ReadBotToken(tokenPath)
			if err != nil {
				return config.TelegramSettings{}, err
			}
		} else {
			token = val
			if err := SaveBotToken(tokenPath, token); err != nil {
				return config.TelegramSettings{}, fmt.Errorf("save token: %w", err)
			}
			if err := writef(out, "Saved bot token to %s\n", tokenPath); err != nil {
				return config.TelegramSettings{}, err
			}
		}
	} else {
		if err := writeln(errOut, "Enter your Telegram bot token (from @BotFather). Input may be visible — beware shoulder-surfing."); err != nil {
			return config.TelegramSettings{}, err
		}
		val, err := p.Line("Bot token: ")
		if err != nil {
			return config.TelegramSettings{}, err
		}
		token = strings.TrimSpace(val)
		if token == "" {
			return config.TelegramSettings{}, fmt.Errorf("empty bot token")
		}
		if err := SaveBotToken(tokenPath, token); err != nil {
			return config.TelegramSettings{}, fmt.Errorf("save token: %w", err)
		}
		if err := writef(out, "Saved bot token to %s\n", tokenPath); err != nil {
			return config.TelegramSettings{}, err
		}
	}

	approverID := strings.TrimSpace(existing.ApproverUserID)
	chatID := strings.TrimSpace(existing.ChatID)
	if allowKeep && approverID != "" && chatID != "" {
		if err := writef(out, "  current approver_user_id: %s\n", approverID); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writef(out, "  current chat_id: %s\n", chatID); err != nil {
			return config.TelegramSettings{}, err
		}
		val, err := p.LineOrKeep("Approver user id", approverID)
		if err != nil {
			return config.TelegramSettings{}, err
		}
		if val != approverID {
			approverID = val
			chatID, err = p.LineOrKeep("Chat id", chatID)
			if err != nil {
				return config.TelegramSettings{}, err
			}
		}
		if approverID == "" {
			return config.TelegramSettings{}, fmt.Errorf("approver user id required")
		}
		if _, err := strconv.ParseInt(approverID, 10, 64); err != nil {
			return config.TelegramSettings{}, fmt.Errorf("approver user id must be numeric")
		}
		if chatID == "" {
			chatID = approverID
		}
		return config.TelegramSettings{
			BotTokenFile:   tokenPath,
			ApproverUserID: approverID,
			ChatID:         chatID,
		}, nil
	}

	if err := writeBlank(out); err != nil {
		return config.TelegramSettings{}, err
	}
	for _, line := range []string{
		"Telegram setup:",
		"  1. Open Telegram and find your bot",
		"  2. Send /start to the bot",
		"  3. Return here and press Enter",
	} {
		if err := writeln(out, line); err != nil {
			return config.TelegramSettings{}, err
		}
	}
	if _, err := p.Line("Press Enter when you have sent /start... "); err != nil {
		return config.TelegramSettings{}, err
	}

	ctx := context.Background()
	discoveredApprover, discoveredChat, err := DiscoverApprover(ctx, token, nil, "")
	if err != nil {
		if err := writef(errOut, "Discovery failed: %v\n", err); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writeln(errOut, "Retrying once..."); err != nil {
			return config.TelegramSettings{}, err
		}
		discoveredApprover, discoveredChat, err = DiscoverApprover(ctx, token, nil, "")
	}
	if err != nil {
		if err := writeln(errOut, "Could not detect your Telegram user id automatically."); err != nil {
			return config.TelegramSettings{}, err
		}
		if err := writeln(errOut, "Find your numeric id (e.g. message @userinfobot) and enter it below."); err != nil {
			return config.TelegramSettings{}, err
		}
		discoveredApprover, err = p.Line("Approver user id: ")
		if err != nil {
			return config.TelegramSettings{}, err
		}
		discoveredApprover = strings.TrimSpace(discoveredApprover)
		if discoveredApprover == "" {
			return config.TelegramSettings{}, fmt.Errorf("approver user id required")
		}
		if _, err := strconv.ParseInt(discoveredApprover, 10, 64); err != nil {
			return config.TelegramSettings{}, fmt.Errorf("approver user id must be numeric")
		}
		discoveredChat = discoveredApprover
	}

	return config.TelegramSettings{
		BotTokenFile:   tokenPath,
		ApproverUserID: discoveredApprover,
		ChatID:         discoveredChat,
	}, nil
}
