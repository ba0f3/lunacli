package approval

import (
	"fmt"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

// RemoteProvidersFromSettings builds notification providers from config files and env.
// Recognized provider names: fake, telegram.
func RemoteProvidersFromSettings(s *config.Settings, svc *Service) (*ProviderSet, error) {
	raw := strings.TrimSpace(s.ApprovalProvider())
	var names []string
	if raw == "" {
		names = []string{"fake"}
	} else {
		for _, part := range strings.Split(raw, ",") {
			n := strings.TrimSpace(strings.ToLower(part))
			if n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			names = []string{"fake"}
		}
	}

	seen := make(map[string]struct{})
	var providers []Provider
	for _, name := range names {
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}

		switch name {
		case "fake":
			providers = append(providers, NewFakeProvider(svc, "fake"))
		case "telegram":
			tg, err := NewTelegramProviderFromSettings(svc, s)
			if err != nil {
				return nil, fmt.Errorf("telegram approval provider: %w", err)
			}
			providers = append(providers, tg)
		default:
			return nil, fmt.Errorf("unknown approval provider entry %q", name)
		}
	}

	return NewProviderSet(providers...), nil
}

// RemoteProvidersFromEnv loads settings from JSON config files then builds providers.
func RemoteProvidersFromEnv(svc *Service) (*ProviderSet, error) {
	s, err := config.LoadSettings()
	if err != nil {
		return nil, err
	}
	return RemoteProvidersFromSettings(s, svc)
}
