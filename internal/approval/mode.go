package approval

import (
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

// Config holds approval settings for luna serve.
type Config struct {
	TTL time.Duration
}

// LoadConfig reads approval TTL from config files then environment overrides.
func LoadConfig(s *config.Settings) (Config, error) {
	ttl, err := s.ApprovalTTL()
	if err != nil {
		return Config{}, err
	}
	return Config{TTL: ttl}, nil
}

// LoadConfigFromEnv loads JSON config tiers then applies LUNA_APPROVAL_TTL env override.
func LoadConfigFromEnv() (Config, error) {
	s, err := config.LoadSettings()
	if err != nil {
		return Config{}, err
	}
	return LoadConfig(s)
}
