package approval

import (
	"encoding/json"
)

// Approval lifecycle status values for pending records and decisions.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusConsumed = "consumed"
)

const executeRemoteToolName = "execute_remote"

// ExecuteRemoteRequest is the redacted, fingerprinted payload for execute_remote approvals.
type ExecuteRemoteRequest struct {
	Tool       string  `json:"tool"`
	Host       string  `json:"host"`
	Command    string  `json:"command"`
	TimeoutSec float64 `json:"timeout_sec"`
}

// CanonicalJSON marshals v to compact JSON for stable fingerprinting.
func CanonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// BuildExecuteRemoteRequest builds the redacted request body and its SHA-256 fingerprint.
func BuildExecuteRemoteRequest(host, command string, timeoutSec float64) (ExecuteRemoteRequest, []byte, string, error) {
	req := ExecuteRemoteRequest{
		Tool:       executeRemoteToolName,
		Host:       host,
		Command:    RedactSecrets(command),
		TimeoutSec: timeoutSec,
	}
	body, err := CanonicalJSON(req)
	if err != nil {
		return ExecuteRemoteRequest{}, nil, "", err
	}
	return req, body, ComputeFingerprint(body), nil
}
