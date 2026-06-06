package onboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapMTLS(t *testing.T) {
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpEHI0oxMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFkx1\nbmEgVGVzdCBDQSBDbGllbnQ=\n-----END CERTIFICATE-----\n")
	clientCertPEM := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpEHI0oxMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMTFkx1\nbmEgVGVzdCBDZXJ0\n-----END CERTIFICATE-----\n"

	mux := http.NewServeMux()
	mux.HandleFunc(mtlsCAPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc(mtlsEnrollPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(enrollTokenHeader); got != "secret-token" {
			http.Error(w, "invalid enroll token", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		var req struct {
			CSRPEM string `json:"csr_pem"`
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.CSRPEM) == "" {
			http.Error(w, "csr_pem required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate_pem": clientCertPEM})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	if err := BootstrapMTLS(context.Background(), MTLSEnrollOptions{
		ProxyURL:    srv.URL,
		CertsDir:    dir,
		EnrollToken: "secret-token",
		Force:       true,
	}); err != nil {
		t.Fatalf("BootstrapMTLS() error = %v", err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key", "client.csr.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("client.key mode = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestBootstrapMTLS_InvalidToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(mtlsCAPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"))
	})
	mux.HandleFunc(mtlsEnrollPath, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid enroll token", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	err := BootstrapMTLS(context.Background(), MTLSEnrollOptions{
		ProxyURL:    srv.URL,
		CertsDir:    t.TempDir(),
		EnrollToken: "wrong",
		Force:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid enroll token") {
		t.Fatalf("BootstrapMTLS() error = %v, want invalid enroll token", err)
	}
}

func TestMTLSMaterialReady(t *testing.T) {
	dir := t.TempDir()
	if mtlsMaterialReady(dir) {
		t.Fatal("empty dir should not be ready")
	}
	write := func(name, content string, perm os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), perm); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n", 0o644)
	write("client.crt", "-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----\n", 0o644)
	write("client.key", "secret\n", 0o600)
	if !mtlsMaterialReady(dir) {
		t.Fatal("expected ready")
	}
}

func TestResolveEnrollTokenFromEnv(t *testing.T) {
	t.Setenv("LUNA_MTLS_ENROLL_TOKEN", "from-env")
	var out strings.Builder
	p := NewPrompter(strings.NewReader(""), &out)
	token, err := resolveEnrollToken(p, &out, "")
	if err != nil {
		t.Fatal(err)
	}
	if token != "from-env" {
		t.Fatalf("token = %q", token)
	}
}
