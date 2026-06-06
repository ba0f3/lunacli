package ssh

import (
	"context"
	"fmt"

	gossh "golang.org/x/crypto/ssh"
)

type agentAuth struct{}

func (a *agentAuth) SignersFor(ctx context.Context, t Target) ([]gossh.Signer, error) {
	_ = ctx
	_ = t
	signers, err := sharedAgentSigners()
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("transport.mode luna-agent requires SSH_AUTH_SOCK pointing at luna-agent")
	}
	return signers, nil
}
