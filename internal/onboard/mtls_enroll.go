package onboard

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

const (
	mtlsCAPath         = "/api/v1/mtls/ca"
	mtlsEnrollPath     = "/api/v1/mtls/enroll"
	enrollTokenHeader  = "X-Luna-Enroll-Token"
	defaultMTLSTimeout = 30 * time.Second
)

// MTLSEnrollOptions configures automated mTLS bootstrap against luna-proxy.
type MTLSEnrollOptions struct {
	ProxyURL    string
	CertsDir    string
	EnrollToken string
	Force       bool
	Timeout     time.Duration
}

// DefaultMTLSCertsDir returns ~/.config/luna/certs (lunacli default).
func DefaultMTLSCertsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}
	return filepath.Join(home, ".config", "luna", "certs"), nil
}

func mtlsMaterialReady(dir string) bool {
	dir = filepath.Clean(dir)
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			return false
		}
		if name != "client.key" && !looksLikePEMCert(data) {
			return false
		}
	}
	return true
}

// BootstrapMTLS downloads the proxy CA, generates a client key + CSR, and enrolls client.crt.
func BootstrapMTLS(ctx context.Context, opts MTLSEnrollOptions) error {
	opts = opts.withDefaults()
	if opts.EnrollToken == "" {
		return fmt.Errorf("enroll token required (set LUNA_MTLS_ENROLL_TOKEN or enter during onboard)")
	}
	if err := os.MkdirAll(opts.CertsDir, 0o700); err != nil {
		return fmt.Errorf("create certs dir: %w", err)
	}
	if _, err := fetchProxyCA(ctx, opts); err != nil {
		return fmt.Errorf("download CA: %w", err)
	}
	if err := generateClientKeyAndCSR(opts); err != nil {
		return err
	}
	if _, err := enrollClientCSR(ctx, opts); err != nil {
		return fmt.Errorf("enroll client: %w", formatMTLSEnrollError(err, opts.CertsDir))
	}
	return nil
}

func fetchProxyCA(ctx context.Context, opts MTLSEnrollOptions) (string, error) {
	dest := filepath.Join(opts.CertsDir, "ca.crt")
	if !opts.Force {
		if data, err := os.ReadFile(dest); err == nil && looksLikePEMCert(data) {
			return dest, nil
		}
	}
	url := strings.TrimRight(opts.ProxyURL, "/") + mtlsCAPath
	client := mtlsHTTPClient(opts.CertsDir, true, opts.Timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", mtlsCAPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d: %s", mtlsCAPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if !looksLikePEMCert(body) {
		return "", fmt.Errorf("GET %s: response is not a PEM certificate", mtlsCAPath)
	}
	if err := writeFileAtomic(dest, body, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

func generateClientKeyAndCSR(opts MTLSEnrollOptions) error {
	keyPath := filepath.Join(opts.CertsDir, "client.key")
	csrPath := filepath.Join(opts.CertsDir, "client.csr.pem")
	if !opts.Force {
		if fileExists(keyPath) && fileExists(csrPath) {
			return nil
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "lunacli",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if err := writeFileAtomic(csrPath, csrPEM, 0o644); err != nil {
		return err
	}
	return nil
}

func enrollClientCSR(ctx context.Context, opts MTLSEnrollOptions) (string, error) {
	csrPath := filepath.Join(opts.CertsDir, "client.csr.pem")
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return "", fmt.Errorf("read client.csr.pem: %w", err)
	}
	payload, err := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return "", err
	}

	url := strings.TrimRight(opts.ProxyURL, "/") + mtlsEnrollPath
	client := mtlsHTTPClient(opts.CertsDir, false, opts.Timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(enrollTokenHeader, opts.EnrollToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", mtlsEnrollPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("POST %s: HTTP %d: %s", mtlsEnrollPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode enroll response: %w", err)
	}
	if !looksLikePEMCert([]byte(out.CertificatePEM)) {
		return "", fmt.Errorf("enroll response missing certificate_pem")
	}
	dest := filepath.Join(opts.CertsDir, "client.crt")
	if err := writeFileAtomic(dest, []byte(out.CertificatePEM), 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

func mtlsHTTPClient(certsDir string, insecure bool, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultMTLSTimeout
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !insecure {
		if pool, err := loadCAPool(filepath.Join(certsDir, "ca.crt")); err == nil {
			tlsCfg.RootCAs = pool
		}
	} else {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // bootstrap first contact only
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

func loadCAPool(caPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("parse CA PEM")
	}
	return pool, nil
}

func looksLikePEMCert(pemBytes []byte) bool {
	return bytes.Contains(pemBytes, []byte("BEGIN CERTIFICATE"))
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".luna-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func formatMTLSEnrollError(err error, certsDir string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "invalid enroll token") || strings.Contains(msg, "HTTP 401") {
		return fmt.Errorf(`%w

Check mtls_enroll_token on the proxy matches the token you entered.
On the proxy: set mtls_enroll_token in proxy.yml and restart luna-proxy.`, err)
	}
	if strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:") {
		return fmt.Errorf(`%w

TLS trust problem talking to luna-proxy. Delete %s/ca.crt and re-run onboard enroll,
or ensure the proxy URL hostname matches the certificate from luna-proxy setup.`, err, certsDir)
	}
	return err
}

func (o MTLSEnrollOptions) withDefaults() MTLSEnrollOptions {
	if o.Timeout <= 0 {
		o.Timeout = defaultMTLSTimeout
	}
	o.ProxyURL = strings.TrimSpace(o.ProxyURL)
	o.CertsDir = filepath.Clean(o.CertsDir)
	o.EnrollToken = strings.TrimSpace(o.EnrollToken)
	return o
}

func resolveEnrollToken(p *Prompter, out io.Writer, existing string) (string, error) {
	if token := strings.TrimSpace(os.Getenv("LUNA_MTLS_ENROLL_TOKEN")); token != "" {
		if err := writef(out, "  using enroll token from LUNA_MTLS_ENROLL_TOKEN\n"); err != nil {
			return "", err
		}
		return token, nil
	}
	if strings.TrimSpace(existing) != "" {
		val, err := p.LineOrKeep("Enroll token (from proxy admin)", existing)
		if err != nil {
			return "", err
		}
		if val == "" {
			return "", fmt.Errorf("enroll token required")
		}
		return val, nil
	}
	if err := writeln(out, "  Proxy admin: set mtls_enroll_token in proxy.yml on luna-proxy."); err != nil {
		return "", err
	}
	val, err := p.Line("Enroll token: ")
	if err != nil {
		return "", err
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return "", fmt.Errorf("enroll token required")
	}
	return val, nil
}

func promptMTLSMaterial(
	p *Prompter,
	out, errOut io.Writer,
	endpoint string,
	existing config.ProxyTransportSettings,
	allowKeep bool,
) (config.ProxyTransportSettings, error) {
	certsDir, err := DefaultMTLSCertsDir()
	if err != nil {
		return config.ProxyTransportSettings{}, err
	}

	if err := writeBlank(out); err != nil {
		return config.ProxyTransportSettings{}, err
	}
	if err := writeln(out, "mTLS client material (for luna-proxy):"); err != nil {
		return config.ProxyTransportSettings{}, err
	}
	if err := writef(out, "  Default directory: %s\n", certsDir); err != nil {
		return config.ProxyTransportSettings{}, err
	}

	if mtlsMaterialReady(certsDir) {
		if err := writef(out, "  existing credentials found under %s\n", certsDir); err != nil {
			return config.ProxyTransportSettings{}, err
		}
		if allowKeep {
			keep, err := promptKeepOrUpdate(p, "mTLS client credentials")
			if err != nil {
				return config.ProxyTransportSettings{}, err
			}
			if keep {
				if err := writef(out, "Keeping existing mTLS credentials.\n"); err != nil {
					return config.ProxyTransportSettings{}, err
				}
				return proxyTransportWithEndpoint(endpoint, existing), nil
			}
		}
	}

	idx, err := p.Choice("mTLS client credentials", []string{
		"Enroll automatically (download CA, generate key, enroll)",
		"Skip for now (install certs manually before luna serve)",
	}, 0)
	if err != nil {
		return config.ProxyTransportSettings{}, err
	}
	if idx == 1 {
		if err := writeln(out, "  Skipped automatic enrollment."); err != nil {
			return config.ProxyTransportSettings{}, err
		}
		if err := writeln(out, "  Install ca.crt, client.crt, and client.key under ~/.config/luna/certs/ before luna serve."); err != nil {
			return config.ProxyTransportSettings{}, err
		}
		return config.ProxyTransportSettings{Endpoint: endpoint}, nil
	}

	token, err := resolveEnrollToken(p, out, "")
	if err != nil {
		return config.ProxyTransportSettings{}, err
	}
	if err := writef(out, "Enrolling mTLS client against %s ...\n", endpoint); err != nil {
		return config.ProxyTransportSettings{}, err
	}
	if err := BootstrapMTLS(context.Background(), MTLSEnrollOptions{
		ProxyURL:    endpoint,
		CertsDir:    certsDir,
		EnrollToken: token,
		Force:       true,
	}); err != nil {
		return config.ProxyTransportSettings{}, err
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := writef(out, "  Wrote %s\n", filepath.Join(certsDir, name)); err != nil {
			return config.ProxyTransportSettings{}, err
		}
	}
	if err := writeBlank(out); err != nil {
		return config.ProxyTransportSettings{}, err
	}
	_ = errOut
	return config.ProxyTransportSettings{Endpoint: endpoint}, nil
}

func proxyTransportWithEndpoint(endpoint string, existing config.ProxyTransportSettings) config.ProxyTransportSettings {
	out := existing
	out.Endpoint = endpoint
	return out
}
