package ssh

import (
	"context"
	"fmt"
	"log"

	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

// AuthProvider supplies SSH signers for a target.
type AuthProvider interface {
	SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error)
}

// NewAuthProvider selects transport auth for remote SSH.
func NewAuthProvider(cfg *config.Settings) (AuthProvider, error) {
	if cfg == nil {
		return &directAuth{}, nil
	}
	switch cfg.TransportMode() {
	case "proxy":
		if cfg.ProxyEndpoint() == "" {
			return nil, fmt.Errorf("transport.mode proxy requires transport.proxy.endpoint or LUNA_PROXY_ENDPOINT")
		}
		return newProxyAuth(cfg)
	case "luna-agent":
		log.Printf("[SSH] WARNING: transport.mode=luna-agent is not recommended (weak target binding)")
		return &agentAuth{}, nil
	case "direct":
		log.Printf("[SSH] WARNING: transport.mode=direct is not recommended (no proxy access approval)")
		return &directAuth{}, nil
	default:
		return nil, fmt.Errorf("unknown transport.mode %q", cfg.TransportMode())
	}
}
