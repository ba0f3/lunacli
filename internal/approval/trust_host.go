package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ba0f3/lunacli/internal/config"
	gossh "golang.org/x/crypto/ssh"
)

const trustHostToolName = "trust_host"

// TrustHostRequest is the fingerprinted payload for SSH host-key trust approvals.
type TrustHostRequest struct {
	Tool        string `json:"tool"`
	Alias       string `json:"alias"`
	Host        string `json:"host"`
	HostTarget  string `json:"host_target"`
	HostKey     string `json:"host_key"`
	Fingerprint string `json:"fingerprint"`
}

// BuildTrustHostRequest builds the canonical JSON body and SHA-256 fingerprint.
func BuildTrustHostRequest(alias, hostTarget, canonicalHost, hostKeyLine, fingerprint string) (TrustHostRequest, []byte, string, error) {
	req := TrustHostRequest{
		Tool:        trustHostToolName,
		Alias:       alias,
		Host:        canonicalHost,
		HostTarget:  hostTarget,
		HostKey:     hostKeyLine,
		Fingerprint: fingerprint,
	}
	body, err := CanonicalJSON(req)
	if err != nil {
		return TrustHostRequest{}, nil, "", err
	}
	return req, body, ComputeFingerprint(body), nil
}

func (req TrustHostRequest) summary() string {
	return fmt.Sprintf("trust host %s (%s)", req.Alias, req.Fingerprint)
}

func trustHostNotifyRequest(req TrustHostRequest) ExecuteRemoteRequest {
	return ExecuteRemoteRequest{
		Tool:    trustHostToolName,
		Host:    req.Host,
		Command: req.summary() + "\nkey: " + req.HostKey,
	}
}

// WaitTrustHostApproval blocks until Telegram approves adding the host to hosts.yml.
func (g *Gate) WaitTrustHostApproval(ctx context.Context, alias, hostTarget, canonicalHost, configDir string, pub gossh.PublicKey) error {
	if g == nil || g.svc == nil {
		return fmt.Errorf("host trust approval is not configured")
	}
	if pub == nil {
		return fmt.Errorf("host trust approval requires server public key")
	}

	keyLine := config.FormatHostKeyLine(pub)
	fingerprint := gossh.FingerprintSHA256(pub)
	req, body, fp, err := BuildTrustHostRequest(alias, hostTarget, canonicalHost, keyLine, fingerprint)
	if err != nil {
		return err
	}

	pending, err := g.svc.CreatePendingTrustHost(req, body, fp)
	if err != nil {
		return fmt.Errorf("register host trust approval: %w", err)
	}

	if g.providers != nil {
		if notifyErr := g.providers.NotifyAll(pending, trustHostNotifyRequest(req)); notifyErr != nil {
			return fmt.Errorf("notify host trust approval: %w", notifyErr)
		}
	}

	waitCtx := ctx
	if deadline, ok := ctx.Deadline(); !ok || pending.ExpiresAt.Before(deadline) {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithDeadline(ctx, pending.ExpiresAt)
		defer cancel()
	}

	status, err := g.svc.WaitForDecision(waitCtx, pending.ID)
	if err != nil {
		return err
	}
	if status != StatusApproved {
		return ErrDenied
	}
	if err := g.svc.VerifyAndConsumeTrustHost(pending.ID, req, body, fp); err != nil {
		return err
	}

	entry := config.HostEntry{
		Alias:   req.Alias,
		Host:    hostTarget,
		HostKey: keyLine,
	}
	if entry.Host == "" {
		entry.Host = req.Host
	}
	if entry.Alias == "" {
		entry.Alias = alias
	}
	return config.UpsertHostEntry(configDir, entry)
}

// CreatePendingTrustHost inserts a pending host-trust approval.
func (s *Service) CreatePendingTrustHost(req TrustHostRequest, body []byte, fingerprint string) (PendingInfo, error) {
	return s.createPending(
		trustHostToolName,
		req.Host,
		req.summary(),
		body,
		fingerprint,
		"trust_host",
		"unknown SSH host key",
		s.trustHostBinding(req),
	)
}

// VerifyAndConsumeTrustHost validates an approved host-trust request and marks it consumed.
func (s *Service) VerifyAndConsumeTrustHost(id string, req TrustHostRequest, body []byte, fingerprint string) error {
	r, err := s.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if r.Tool != trustHostToolName {
		return ErrMismatch
	}

	switch r.Status {
	case StatusConsumed:
		return ErrConsumed
	case StatusDenied:
		return ErrDenied
	case StatusExpired:
		return ErrExpired
	case StatusPending:
		return ErrMismatch
	case StatusApproved:
	default:
		return ErrMismatch
	}

	now := s.now().UTC()
	if now.After(r.ExpiresAt) {
		return ErrExpired
	}
	if fingerprint != r.Fingerprint {
		return ErrMismatch
	}
	if ComputeFingerprint(body) != fingerprint {
		return ErrMismatch
	}
	if string(body) != string(r.NormalizedBody) {
		return ErrMismatch
	}
	if req.Tool != r.Tool || req.Host != r.Host || req.summary() != r.RedactedCommand {
		return ErrMismatch
	}
	if s.trustHostBinding(req) != r.ExactBinding {
		return ErrMismatch
	}

	if err := s.store.ConsumeApproved(id, now); err != nil {
		return err
	}
	return s.store.AppendAudit(AuditEvent{
		ApprovalID: id,
		EventType:  "consumed",
		Detail:     `{"via":"verify_and_consume_trust_host"}`,
		CreatedAt:  now,
	})
}

func (s *Service) trustHostBinding(req TrustHostRequest) string {
	body, _ := json.Marshal(req)
	return s.bindingMAC(body)
}
