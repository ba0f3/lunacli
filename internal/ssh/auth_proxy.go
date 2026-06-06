// Proxy signing (no SSH relay):
//
// local-ca: RequestCertificate → NewCertSigner
// local-key: hosted proxy key + RequestSignature(agent_sign_data) on SSH auth
//
// Map HTTP/sign errors via mapSDKAccessError → access_errors.go.
package ssh

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/ba0f3/luna-ztrust/sdk"
	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

const (
	proxySignerModeLocalCA  = "local-ca"
	proxySignerModeLocalKey = "local-key"
	proxySignTimeout        = 90 * time.Second
)

type proxySignerClient interface {
	RequestCertificate(ctx context.Context, req sdk.CertRequest) (*gossh.Certificate, ed25519.PrivateKey, error)
	RequestSignature(ctx context.Context, req sdk.SignatureRequest, signData []byte) (*gossh.Signature, error)
	FetchCapabilities(ctx context.Context) (sdk.Capabilities, error)
}

type proxyAuth struct {
	client     proxySignerClient
	signerMode string
	mu         sync.Mutex
	cache      map[string][]gossh.Signer
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
	wrapped := &sdkProxyClient{inner: client}
	caps, err := wrapped.FetchCapabilities(context.Background())
	if err != nil {
		return nil, fmt.Errorf("proxy capabilities: %w", err)
	}
	mode := caps.SignerMode
	if mode == "" {
		mode = proxySignerModeLocalCA
	}
	log.Printf("[SSH] proxy signer_mode=%s loaded_signers=%d sealed=%v", mode, len(caps.LoadedSigners), caps.Sealed)
	return &proxyAuth{
		client:     wrapped,
		signerMode: mode,
		cache:      make(map[string][]gossh.Signer),
	}, nil
}

type sdkProxyClient struct {
	inner *sdk.Client
}

func (c *sdkProxyClient) RequestCertificate(ctx context.Context, req sdk.CertRequest) (*gossh.Certificate, ed25519.PrivateKey, error) {
	return c.inner.RequestCertificate(ctx, req)
}

func (c *sdkProxyClient) RequestSignature(ctx context.Context, req sdk.SignatureRequest, signData []byte) (*gossh.Signature, error) {
	return c.inner.RequestSignature(ctx, req, signData)
}

func (c *sdkProxyClient) FetchCapabilities(ctx context.Context) (sdk.Capabilities, error) {
	return c.inner.FetchCapabilities(ctx)
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
	clientInfo := proxyClientInfo(t)
	if p.signerMode == proxySignerModeLocalKey {
		return p.signersLocalKey(ctx, t, targetIP, clientInfo)
	}
	return p.signersLocalCA(ctx, t, targetIP, clientInfo)
}

func proxyClientInfo(t Target) sdk.ClientInfo {
	sourceUser := t.User
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		sourceUser = u.Username
	}
	return sdk.ClientInfo{
		SourceUser:    sourceUser,
		ClientName:    "lunacli",
		ClientVersion: "2.0.0",
	}
}

func (p *proxyAuth) signersLocalCA(ctx context.Context, t Target, targetIP string, client sdk.ClientInfo) ([]gossh.Signer, error) {
	// The current proxy SDK has no target-port field. Lunacli still binds and
	// dials the exact approved port locally; proxy-side port policy requires an
	// upstream SDK/proxy contract extension.
	cert, priv, err := p.client.RequestCertificate(ctx, sdk.CertRequest{
		TargetUser: t.User,
		TargetIP:   targetIP,
		Client:     client,
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

func (p *proxyAuth) signersLocalKey(ctx context.Context, t Target, targetIP string, client sdk.ClientInfo) ([]gossh.Signer, error) {
	caps, err := p.client.FetchCapabilities(ctx)
	if err != nil {
		return nil, mapSDKAccessError(fmt.Errorf("GET capabilities: %w", err), t)
	}
	fp, pub, err := selectLoadedSigner(caps)
	if err != nil {
		return nil, fmt.Errorf("%s", FormatAccessError(t, err))
	}
	req := sdk.SignatureRequest{
		TargetUser:         t.User,
		TargetIP:           targetIP,
		HostKeyFingerprint: fp,
		SignatureFormat:    pub.Type(),
		Client:             client,
	}
	return []gossh.Signer{&hostedKeySigner{
		pub:    pub,
		client: p.client,
		req:    req,
	}}, nil
}

func selectLoadedSigner(caps sdk.Capabilities) (fingerprint string, pub gossh.PublicKey, err error) {
	if caps.Sealed {
		return "", nil, fmt.Errorf("proxy keystore is sealed; on the proxy: luna-proxy key load")
	}
	if len(caps.LoadedSigners) == 0 {
		return "", nil, fmt.Errorf("no signing keys loaded on proxy (use: luna-proxy key load)")
	}
	if len(caps.LoadedSigners) == 1 {
		return loadedSignerKey(caps.LoadedSigners[0])
	}
	var lastErr error
	for _, ls := range caps.LoadedSigners {
		fp, pub, err := loadedSignerKey(ls)
		if err == nil {
			return fp, pub, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", nil, lastErr
	}
	return "", nil, fmt.Errorf("no usable signing keys in proxy capabilities")
}

func loadedSignerKey(ls sdk.LoadedSigner) (string, gossh.PublicKey, error) {
	line := strings.TrimSpace(ls.PublicKey)
	if line == "" {
		return "", nil, fmt.Errorf("proxy signer %q missing public_key in capabilities", ls.Fingerprint)
	}
	pub, err := parseSSHPublicKeyLine(line)
	if err != nil {
		return "", nil, err
	}
	fp := normalizeSignerFingerprint(ls.Fingerprint)
	if fp == "" {
		fp = sshPublicKeyFingerprint(pub)
	}
	return fp, pub, nil
}

func parseSSHPublicKeyLine(line string) (gossh.PublicKey, error) {
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		pub, err = gossh.ParsePublicKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("parse hosted public key: %w", err)
		}
	}
	return pub, nil
}

func normalizeSignerFingerprint(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "SHA256:")
	return strings.TrimRight(s, "=")
}

func sshPublicKeyFingerprint(pub gossh.PublicKey) string {
	return normalizeSignerFingerprint(gossh.FingerprintSHA256(pub))
}

type hostedKeySigner struct {
	pub     gossh.PublicKey
	client  proxySignerClient
	req     sdk.SignatureRequest
	mu      sync.RWMutex
	hostKey []byte
}

func (s *hostedKeySigner) PublicKey() gossh.PublicKey {
	return s.pub
}

func (s *hostedKeySigner) setDestinationHostKey(key gossh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostKey = append(s.hostKey[:0], key.Marshal()...)
}

func (s *hostedKeySigner) Sign(_ io.Reader, data []byte) (*gossh.Signature, error) {
	s.mu.RLock()
	hostKey := append([]byte(nil), s.hostKey...)
	s.mu.RUnlock()
	if len(hostKey) == 0 {
		return nil, fmt.Errorf("destination host key was not validated before proxy signing")
	}
	req := s.req
	req.DestinationHostPublicKey = hostKey
	ctx, cancel := context.WithTimeout(context.Background(), proxySignTimeout)
	defer cancel()
	sig, err := s.client.RequestSignature(ctx, req, data)
	if err != nil {
		return nil, mapSDKAccessError(err, Target{
			User: s.req.TargetUser,
			Host: s.req.TargetIP,
			Port: "22",
		})
	}
	// SDK tags Format with the ephemeral PoP key; SSH auth must use the hosted key type.
	return &gossh.Signature{Format: s.pub.Type(), Blob: sig.Blob}, nil
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
	orig := err.Error()
	msg := strings.ToLower(orig)
	switch {
	case strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "timeout"),
		strings.Contains(msg, "http 202"),
		strings.Contains(msg, "pending"):
		return fmt.Errorf("%s", FormatAccessError(t, ErrAccessRequired))
	case strings.Contains(msg, "expired"):
		return fmt.Errorf("%s", FormatAccessError(t, ErrAccessExpired))
	case strings.Contains(msg, "invalid ssh session binding"):
		return fmt.Errorf("%s", FormatAccessError(t, proxySignDetailError(orig)))
	case strings.Contains(msg, "agent_sign_data"):
		return fmt.Errorf("%s", FormatAccessError(t, fmt.Errorf("proxy requires local-key signing (signer mode mismatch)")))
	case strings.Contains(msg, "http 403"),
		strings.Contains(msg, "denied"),
		strings.Contains(msg, "rejected"):
		return fmt.Errorf("%s", FormatAccessError(t, ErrAccessDenied))
	case strings.Contains(msg, "http 401"):
		return fmt.Errorf("%s", FormatAccessError(t, proxySignDetailError(orig)))
	default:
		return fmt.Errorf("%s", FormatAccessError(t, err))
	}
}

// proxySignDetailError extracts the proxy HTTP error body from SDK errors like
// "POST sign: HTTP 401: invalid SSH session binding: user-auth request mismatch".
func proxySignDetailError(httpErr string) error {
	const marker = "invalid SSH session binding"
	if i := strings.Index(httpErr, marker); i >= 0 {
		return fmt.Errorf("%s", strings.TrimSpace(httpErr[i:]))
	}
	if i := strings.Index(httpErr, "HTTP "); i >= 0 {
		if j := strings.Index(httpErr[i:], ": "); j >= 0 {
			return fmt.Errorf("%s", strings.TrimSpace(httpErr[i+j+2:]))
		}
	}
	return fmt.Errorf("%s", strings.TrimSpace(httpErr))
}
