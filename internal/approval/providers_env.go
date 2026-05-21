package approval

import (
	"fmt"

	"github.com/ba0f3/lunacli/internal/config"
)

// RequireTelegramProvider returns the Telegram provider required for luna serve.
func RequireTelegramProvider(s *config.Settings, svc *Service) (*TelegramProvider, error) {
	tg, err := NewTelegramProviderFromSettings(svc, s)
	if err != nil {
		return nil, fmt.Errorf("telegram required for luna serve: %w", err)
	}
	return tg, nil
}
