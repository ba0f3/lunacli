package onboard

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

func PromptTransport(p *Prompter, out, errOut io.Writer, existing config.TransportSettings, allowKeep bool) (config.TransportSettings, error) {
	if err := writeBlank(out); err != nil {
		return config.TransportSettings{}, err
	}
	if err := writeln(out, "SSH transport (how lunacli authenticates to remote hosts):"); err != nil {
		return config.TransportSettings{}, err
	}

	if allowKeep && transportConfigured(existing) {
		if err := writef(out, "  current transport.mode: %s\n", displayTransportMode(existing.Mode)); err != nil {
			return config.TransportSettings{}, err
		}
		if existing.Mode == "" || existing.Mode == "proxy" {
			if err := writef(out, "  current transport.proxy.endpoint: %s\n", existing.Proxy.Endpoint); err != nil {
				return config.TransportSettings{}, err
			}
		}
		keep, err := promptKeepOrUpdate(p, "Transport settings")
		if err != nil {
			return config.TransportSettings{}, err
		}
		if keep {
			if err := writef(out, "Keeping transport settings.\n"); err != nil {
				return config.TransportSettings{}, err
			}
			return existing, nil
		}
	} else if allowKeep {
		if err := writef(out, "  current transport.mode: %s\n", displayTransportMode(existing.Mode)); err != nil {
			return config.TransportSettings{}, err
		}
		endpoint := existing.Proxy.Endpoint
		if endpoint == "" {
			endpoint = "(not set)"
		}
		if err := writef(out, "  current transport.proxy.endpoint: %s\n", endpoint); err != nil {
			return config.TransportSettings{}, err
		}
	}

	if err := writeln(out, "  proxy — luna-proxy signs SSH credentials after access approval (recommended)"); err != nil {
		return config.TransportSettings{}, err
	}
	if err := writeln(out, "  direct — local ssh-agent or disk keys (skips proxy access approval)"); err != nil {
		return config.TransportSettings{}, err
	}

	defaultMode := 0
	if allowKeep && existing.Mode == "direct" {
		defaultMode = 1
	}
	modeIdx, err := p.Choice("Transport mode", []string{
		"Proxy signing via luna-proxy (recommended)",
		"Direct ssh-agent / disk keys (not recommended)",
	}, defaultMode)
	if err != nil {
		return config.TransportSettings{}, err
	}
	if modeIdx == 1 {
		if err := writeln(errOut, "warning: direct transport skips luna-proxy access approval."); err != nil {
			return config.TransportSettings{}, err
		}
		return config.TransportSettings{Mode: "direct"}, nil
	}

	endpoint, err := p.LineOrKeep("luna-proxy HTTPS endpoint (e.g. https://proxy.example:8443)", existing.Proxy.Endpoint)
	if err != nil {
		return config.TransportSettings{}, err
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		return config.TransportSettings{}, err
	}

	tls, err := promptMTLSMaterial(p, out, errOut, endpoint, existing.Proxy, allowKeep)
	if err != nil {
		return config.TransportSettings{}, err
	}

	return config.TransportSettings{
		Mode:  "proxy",
		Proxy: tls,
	}, nil
}

func validateProxyEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("luna-proxy endpoint is required for proxy transport mode")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid luna-proxy endpoint URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("luna-proxy endpoint must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("luna-proxy endpoint is missing host")
	}
	return nil
}
