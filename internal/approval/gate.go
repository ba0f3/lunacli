package approval

import (
	"context"
	"fmt"
	"time"

	"github.com/ba0f3/lunacli/internal/engine"
)

// GateKind describes how execute_remote should proceed after policy checks.
type GateKind int

const (
	GateExecute GateKind = iota
	GateBlocked
	GatePermissionRequired
)

// GateResult is the outcome of CheckExecuteRemote.
type GateResult struct {
	Kind              GateKind
	BlockedText       string
	PermissionText    string
	ApprovalID        string
	ExpiresAt         time.Time
	FingerprintPrefix string
	NotifyErr         error // set when a provider Notify fails (first error only)
	SessionGrant      bool  // true when a prior in-process approval covers this call
}

// Gate applies out-of-band approval policy on top of command classification.
type Gate struct {
	cfg       Config
	svc       *Service
	providers *ProviderSet
}

func NewGate(cfg Config, svc *Service, providers *ProviderSet) *Gate {
	return &Gate{cfg: cfg, svc: svc, providers: providers}
}

// WaitForDecision blocks until the approval is decided or ctx ends.
func (g *Gate) WaitForDecision(ctx context.Context, id string) (Status, error) {
	if g.svc == nil {
		return "", fmt.Errorf("approval service not configured")
	}
	return g.svc.WaitForDecision(ctx, id)
}

func (g *Gate) CheckExecuteRemote(check engine.Result, host, command string, timeoutSec float64, approvalID string) GateResult {
	if check.Class == engine.Forbidden {
		return GateResult{Kind: GateBlocked, BlockedText: "BLOCKED: " + check.Reason}
	}
	if check.Class == engine.ReadOnly {
		return GateResult{Kind: GateExecute}
	}

	if g.svc == nil {
		return GateResult{
			Kind:           GatePermissionRequired,
			PermissionText: "PERMISSION_REQUIRED: approval database is not configured.",
		}
	}

	req, body, fp, err := BuildExecuteRemoteRequest(host, command, timeoutSec)
	if err != nil {
		return GateResult{
			Kind:           GatePermissionRequired,
			PermissionText: "PERMISSION_REQUIRED: error building approval: " + err.Error(),
		}
	}

	if approvalID != "" {
		if err := g.svc.VerifyAndConsume(approvalID, req, body, fp); err != nil {
			return GateResult{
				Kind:           GatePermissionRequired,
				PermissionText: fmt.Sprintf("PERMISSION_REQUIRED: approval consumed/invalid: %v", err),
				ApprovalID:     approvalID,
			}
		}
		g.svc.RememberSessionGrant(req)
		return GateResult{Kind: GateExecute}
	}

	if g.svc.HasSessionGrant(req) {
		return GateResult{Kind: GateExecute, SessionGrant: true}
	}

	pending, err := g.svc.CreatePending(executeRemoteToolName, req, body, fp, string(check.Class), check.Reason)
	if err != nil {
		return GateResult{
			Kind:           GatePermissionRequired,
			PermissionText: "PERMISSION_REQUIRED: failed to register approval request: " + err.Error(),
		}
	}
	var notifyErr error
	if g.providers != nil {
		notifyErr = g.providers.NotifyAll(pending, req)
	}

	return GateResult{
		Kind:              GatePermissionRequired,
		PermissionText:    FormatPermissionRequired(check.Reason, req.Command, pending.ID, pending.ExpiresAt, pending.FingerprintPrefix),
		ApprovalID:        pending.ID,
		ExpiresAt:         pending.ExpiresAt,
		FingerprintPrefix: pending.FingerprintPrefix,
		NotifyErr:         notifyErr,
	}
}
