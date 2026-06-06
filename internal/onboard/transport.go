package onboard

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/ba0f3/lunacli/internal/config"
)

func PromptTransport(p *Prompter, out, errOut io.Writer) (config.TransportSettings, error) {
	if err := writeBlank(out); err != nil {
		return config.TransportSettings{}, err
	}
	if err := writeln(out, "SSH transport (how lunacli authenticates to remote hosts):"); err != nil {
		return config.TransportSettings{}, err
	}
	if err := writeln(out, "  proxy — luna-proxy signs SSH credentials after access approval (recommended)"); err != nil {
		return config.TransportSettings{}, err
	}
	if err := writeln(out, "  direct — local ssh-agent or disk keys (skips proxy access approval)"); err != nil {
		return config.TransportSettings{}, err
	}

	modeIdx, err := p.Choice("Transport mode", []string{
		"Proxy signing via luna-proxy (recommended)",
		"Direct ssh-agent / disk keys (not recommended)",
	}, 0)
	if err != nil {
		return config.TransportSettings{}, err
	}
	if modeIdx == 1 {
		if err := writeln(errOut, "warning: direct transport skips luna-proxy access approval."); err != nil {
			return config.TransportSettings{}, err
		}
		return config.TransportSettings{Mode: "direct"}, nil
	}

	endpoint, err := p.Line("luna-proxy HTTPS endpoint (e.g. https://proxy.example:8443): ")
	if err != nil {
		return config.TransportSettings{}, err
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		return config.TransportSettings{}, err
	}

	if err := writeBlank(out); err != nil {
		return config.TransportSettings{}, err
	}
	for _, line := range []string{
		"mTLS client material (for luna-proxy):",
		"  Default: ~/.config/luna/certs/client.crt, client.key, ca.crt",
		"  Override below or set transport.proxy.tls_* in luna.config.json later.",
	} {
		if err := writeln(out, line); err != nil {
			return config.TransportSettings{}, err
		}
	}

	cert, err := p.Line("Client cert path [default]: ")
	if err != nil {
		return config.TransportSettings{}, err
	}
	key, err := p.Line("Client key path [default]: ")
	if err != nil {
		return config.TransportSettings{}, err
	}
	ca, err := p.Line("CA cert path [default]: ")
	if err != nil {
		return config.TransportSettings{}, err
	}

	return config.TransportSettings{
		Mode: "proxy",
		Proxy: config.ProxyTransportSettings{
			Endpoint: endpoint,
			TLSCert:  strings.TrimSpace(cert),
			TLSKey:   strings.TrimSpace(key),
			TLSCA:    strings.TrimSpace(ca),
		},
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
