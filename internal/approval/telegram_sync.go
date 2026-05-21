package approval

import (
	"context"

	"github.com/ba0f3/lunacli/internal/config"
)

// UpdateTelegramMessage edits the stored Telegram approval prompt to reflect the current record status.
// Missing Telegram message metadata or provider config is a no-op. Errors are returned for API failures.
func (s *Service) UpdateTelegramMessage(settings *config.Settings, id string) error {
	rec, err := s.Get(id)
	if err != nil {
		return err
	}
	if rec.TelegramMessageID == 0 {
		return nil
	}

	if settings == nil {
		return nil
	}
	tg, err := NewTelegramProviderFromSettings(s, settings)
	if err != nil {
		return nil
	}

	statusLabel := telegramStatusLabel(rec.Status)
	if statusLabel == "" {
		return nil
	}

	detail := telegramResolvedDetailForProvider(rec, rec.Approver, "cli", nil)
	text := formatTelegramResolvedMessage(rec, statusLabel, detail)
	return tg.editApprovalMessage(context.Background(), rec.TelegramChatID, rec.TelegramMessageID, text)
}

func telegramStatusLabel(status Status) string {
	switch status {
	case StatusApproved:
		return "APPROVED"
	case StatusDenied:
		return "DENIED"
	case StatusExpired:
		return "EXPIRED"
	case StatusConsumed:
		return "CONSUMED"
	case StatusPending:
		return "PENDING"
	default:
		return ""
	}
}
