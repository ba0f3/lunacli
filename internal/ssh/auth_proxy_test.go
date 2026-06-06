package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/sdk"
	gossh "golang.org/x/crypto/ssh"
)

func TestMapSDKAccessError_SessionBindingDetail(t *testing.T) {
	err := mapSDKAccessError(
		fmt.Errorf("POST sign: HTTP 401: invalid SSH session binding: user-auth request mismatch"),
		Target{Raw: "root@10.9.5.15:22"},
	)
	if !strings.Contains(err.Error(), "user-auth request mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestMapSDKAccessError_DeniedHTTP(t *testing.T) {
	err := mapSDKAccessError(fmt.Errorf("POST sign: HTTP 403: denied"), Target{Raw: "u@h:22"})
	if AccessErrorMessage(err) == "" {
		t.Fatalf("got %v", err)
	}
}

func TestProxyAuth_FakeClientDenied(t *testing.T) {
	p := &proxyAuth{
		client:     &fakeProxyClient{err: fmt.Errorf("GET wait: HTTP 403: rejected")},
		signerMode: proxySignerModeLocalCA,
		cache:      make(map[string][]gossh.Signer),
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

func TestHostedKeySigner_BindsAcceptedDestinationHostKey(t *testing.T) {
	_, hostedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hosted, err := gossh.NewSignerFromKey(hostedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, destinationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := gossh.NewSignerFromKey(destinationPrivate)
	if err != nil {
		t.Fatal(err)
	}

	client := &fakeProxyClient{err: io.EOF}
	signer := &hostedKeySigner{
		pub:    hosted.PublicKey(),
		client: client,
		req: sdk.SignatureRequest{
			TargetUser: "alice",
			TargetIP:   "192.0.2.10",
		},
	}
	signer.setDestinationHostKey(destination.PublicKey())

	signData := []byte("ssh userauth sign data")
	_, _ = signer.Sign(rand.Reader, signData)
	if got, want := string(client.signatureRequest.DestinationHostPublicKey), string(destination.PublicKey().Marshal()); got != want {
		t.Fatalf("destination host public key = %x, want %x", got, want)
	}
	if got, want := string(client.lastSignData), string(signData); got != want {
		t.Fatalf("sign data forwarded unchanged = %q, want %q", got, want)
	}
}

func TestHostedKeySigner_RejectsSignBeforeHostKeyValidation(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hosted, err := gossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	signer := &hostedKeySigner{pub: hosted.PublicKey(), client: &fakeProxyClient{}}

	if _, err := signer.Sign(rand.Reader, []byte("data")); err == nil {
		t.Fatal("Sign() error = nil, want missing destination host key error")
	}
}

type fetchCountProxyClient struct {
	fakeProxyClient
	fetchCalls int
}

func (f *fetchCountProxyClient) FetchCapabilities(ctx context.Context) (sdk.Capabilities, error) {
	f.fetchCalls++
	return f.fakeProxyClient.FetchCapabilities(ctx)
}

func TestSignersLocalKey_ReusesInitCapabilities(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	line := string(gossh.MarshalAuthorizedKey(pub))

	client := &fetchCountProxyClient{}
	p := &proxyAuth{
		client:     client,
		signerMode: proxySignerModeLocalKey,
		caps: sdk.Capabilities{
			SignerMode: proxySignerModeLocalKey,
			LoadedSigners: []sdk.LoadedSigner{{
				PublicKey:   line,
				Fingerprint: gossh.FingerprintSHA256(pub),
			}},
		},
		cache: make(map[string][]gossh.Signer),
	}

	signers, err := p.signersLocalKey(context.Background(), Target{User: "root", Host: "127.0.0.1", Port: "22"}, "127.0.0.1", sdk.ClientInfo{})
	if err != nil {
		t.Fatalf("signersLocalKey: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("signers = %d, want 1", len(signers))
	}
	if client.fetchCalls != 0 {
		t.Fatalf("FetchCapabilities called %d times during signersLocalKey, want 0 (use startup cache)", client.fetchCalls)
	}
}
