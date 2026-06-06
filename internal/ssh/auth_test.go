package ssh

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/ba0f3/luna-ztrust/sdk"
	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

func TestNewAuthProvider_DirectUsesDiskAndAgent(t *testing.T) {
	cfg := &config.Settings{}
	// Settings with nil file still gets direct via explicit mode
	t.Setenv("LUNA_TRANSPORT_MODE", "direct")
	cfg = &config.Settings{}
	prov, err := NewAuthProvider(cfg)
	if err != nil {
		t.Fatalf("NewAuthProvider: %v", err)
	}
	if _, ok := prov.(*directAuth); !ok {
		t.Fatalf("got %T, want *directAuth", prov)
	}
}

func TestDirectAuth_SignersFor_EmptyHost(t *testing.T) {
	d := &directAuth{}
	signers, err := d.SignersFor(context.Background(), Target{Host: "nonexistent.example.invalid"})
	if err != nil {
		t.Fatalf("SignersFor: %v", err)
	}
	_ = signers
}

type fakeProxyClient struct {
	err error
}

func (f *fakeProxyClient) RequestCertificate(ctx context.Context, req sdk.CertRequest) (*gossh.Certificate, ed25519.PrivateKey, error) {
	_ = ctx
	_ = req
	return nil, nil, f.err
}

func TestProxyAuth_MapDenied(t *testing.T) {
	p := &proxyAuth{
		client: &fakeProxyClient{err: ErrAccessDenied},
		cache:  make(map[string][]gossh.Signer),
	}
	_, err := p.SignersFor(context.Background(), Target{User: "u", Host: "127.0.0.1", Port: "22", Raw: "u@127.0.0.1:22"})
	if err == nil {
		t.Fatal("want error")
	}
	if got := err.Error(); got == "" || got[:len("ACCESS_")] != "ACCESS_" {
		// mapSDKAccessError wraps FormatAccessError
		if AccessErrorMessage(err) == "" && !containsPrefix(got, "ACCESS_") {
			t.Fatalf("got %q", got)
		}
	}
}

func containsPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
