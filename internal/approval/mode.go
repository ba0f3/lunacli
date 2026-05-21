package approval

import (
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

// Config holds approval transport settings.
type Config struct {
	Store string
	TTL   time.Duration
}

// LoadConfig reads approval settings from config files then environment overrides.
func LoadConfig(s *config.Settings) (Config, error) {
	ttl, err := s.ApprovalTTL()
	if err != nil {
		return Config{}, err
	}
	return Config{
		Store: s.ApprovalStore(),
		TTL:   ttl,
	}, nil
}

// LoadConfigFromEnv loads JSON config tiers then applies LUNA_APPROVAL_* env overrides.
func LoadConfigFromEnv() (Config, error) {
	s, err := config.LoadSettings()
	if err != nil {
		return Config{}, err
	}
	return LoadConfig(s)
}
