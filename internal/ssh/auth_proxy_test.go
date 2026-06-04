package ssh

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/ba0f3/luna-ztrust/sdk"
	gossh "golang.org/x/crypto/ssh"
)

func TestMapSDKAccessError_DeniedHTTP(t *testing.T) {
	err := mapSDKAccessError(fmt.Errorf("POST sign: HTTP 403: denied"), Target{Raw: "u@h:22"})
	if AccessErrorMessage(err) == "" {
		t.Fatalf("got %v", err)
	}
}

func TestProxyAuth_FakeClientDenied(t *testing.T) {
	p := &proxyAuth{
		client: &fakeProxyClient{err: fmt.Errorf("GET wait: HTTP 403: rejected")},
		cache:  make(map[string][]gossh.Signer),
	}
	_, err := p.signersForTarget(context.Background(), Target{User: "u", Host: "127.0.0.1", Port: "22"})
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if msg == "" {
		t.Fatal("empty error")
	}
}

// compile-time check fake implements interface
var _ proxySignerClient = (*fakeProxyClient)(nil)

func TestFakeProxyClient_SDKTypes(t *testing.T) {
	var _ proxySignerClient = (*fakeProxyClient)(nil)
	_ = sdk.CertRequest{}
	_ = ed25519.PrivateKey{}
}
