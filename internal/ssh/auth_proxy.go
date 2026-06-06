// Proxy signing (no SSH relay):
//
//	client, err := sdk.NewClient(sdk.Config{ProxyURL: endpoint, TLSCert, TLSRootCAs, ...})
//	cert, priv, err := client.RequestCertificate(ctx, sdk.CertRequest{TargetUser, TargetIP, Client})
//	signer, err := sdk.NewCertSigner(cert, priv)
//
// Map HTTP/sign errors via mapSDKAccessError → access_errors.go.
package ssh

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"os/user"
	"strings"
	"sync"

	"github.com/ba0f3/luna-ztrust/sdk"
	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

type proxySignerClient interface {
	RequestCertificate(ctx context.Context, req sdk.CertRequest) (*gossh.Certificate, ed25519.PrivateKey, error)
}

type proxyAuth struct {
	client proxySignerClient
	mu     sync.Mutex
	cache  map[string][]gossh.Signer
}

func newProxyAuth(cfg *config.Settings) (*proxyAuth, error) {
	certPath, keyPath, caPath := cfg.ProxyTLSPaths()
	tlsCert, pool, err := sdk.LoadTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		return nil, fmt.Errorf("proxy mTLS: %w", err)
	}
	client, err := sdk.NewClient(sdk.Config{
		ProxyURL:   cfg.ProxyEndpoint(),
		TLSCert:    tlsCert,
		TLSRootCAs: pool,
	})
	if err != nil {
		return nil, fmt.Errorf("proxy sdk client: %w", err)
	}
	return &proxyAuth{
		client: &sdkProxyClient{inner: client},
		cache:  make(map[string][]gossh.Signer),
	}, nil
}

type sdkProxyClient struct {
	inner *sdk.Client
}

func (c *sdkProxyClient) RequestCertificate(ctx context.Context, req sdk.CertRequest) (*gossh.Certificate, ed25519.PrivateKey, error) {
	return c.inner.RequestCertificate(ctx, req)
}

func (p *proxyAuth) SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error) {
	key := t.Raw
	if key == "" {
		key = fmt.Sprintf("%s@%s:%s", t.User, t.Host, t.Port)
	}
	p.mu.Lock()
	if cached, ok := p.cache[key]; ok && len(cached) > 0 {
		p.mu.Unlock()
		return cached, nil
	}
	p.mu.Unlock()

	signers, err := p.signersForTarget(ctx, t)
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("%s", FormatAccessError(t, ErrAccessDenied))
	}
	p.mu.Lock()
	p.cache[key] = signers
	p.mu.Unlock()
	return signers, nil
}

func (p *proxyAuth) signersForTarget(ctx context.Context, t Target) ([]gossh.Signer, error) {
	targetIP, err := resolveTargetIP(t.Host, t.Port)
	if err != nil {
		return nil, fmt.Errorf("resolve target %s: %w", t.Host, err)
	}
	sourceUser := t.User
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		sourceUser = u.Username
	}
	cert, priv, err := p.client.RequestCertificate(ctx, sdk.CertRequest{
		TargetUser: t.User,
		TargetIP:   targetIP,
		Client: sdk.ClientInfo{
			SourceUser:    sourceUser,
			ClientName:    "lunacli",
			ClientVersion: "2.0.0",
		},
	})
	if err != nil {
		return nil, mapSDKAccessError(err, t)
	}
	signer, err := sdk.NewCertSigner(cert, priv)
	if err != nil {
		return nil, err
	}
	return []gossh.Signer{signer}, nil
}

func resolveTargetIP(host, port string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if port == "" {
		port = "22"
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses for %s", host)
	}
	return addrs[0], nil
}

func mapSDKAccessError(err error, t Target) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "http 202"),
		strings.Contains(msg, "pending"):
		return fmt.Errorf("%s", FormatAccessError(t, ErrAccessRequired))
	case strings.Contains(msg, "expired"):
		return fmt.Errorf("%s", FormatAccessError(t, ErrAccessExpired))
	case strings.Contains(msg, "http 403"),
		strings.Contains(msg, "http 401"),
		strings.Contains(msg, "denied"),
		strings.Contains(msg, "rejected"):
		return fmt.Errorf("%s", FormatAccessError(t, ErrAccessDenied))
	default:
		return fmt.Errorf("%s", FormatAccessError(t, err))
	}
}
