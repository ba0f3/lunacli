package ssh

import (
	"context"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

type recordingAuth struct {
	calls   []Target
	signers []gossh.Signer
}

func (r *recordingAuth) SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error) {
	r.calls = append(r.calls, t)
	if len(r.signers) > 0 {
		return r.signers, nil
	}
	return nil, nil
}

func TestSignersFor_UsesAuthProvider(t *testing.T) {
	rec := &recordingAuth{}
	p := &Pool{clients: make(map[string]*gossh.Client), auth: rec}
	_, err := p.signersFor(context.Background(), "alice@127.0.0.1:2222")
	if err != nil {
		t.Fatalf("signersFor: %v", err)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(rec.calls))
	}
	if rec.calls[0].User != "alice" || rec.calls[0].Host != "127.0.0.1" || rec.calls[0].Port != "2222" {
		t.Fatalf("target = %+v", rec.calls[0])
	}
}
