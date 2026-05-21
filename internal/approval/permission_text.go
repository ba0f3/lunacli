package approval

import (
	"fmt"
	"time"
)

// FormatPermissionRequired builds MCP-style text for a mutating execute_remote that needs human approval.
func FormatPermissionRequired(reason, command, approvalID string, expiresAt time.Time, fingerprintPrefix string) string {
	return fmt.Sprintf(
		"PERMISSION_REQUIRED: %s\n\nCommand: %q\n\napproval_id: %s\nexpires_at: %s\nfingerprint_prefix: %s\n\nApprove out of band, then retry with the same host and command plus approval_id.",
		reason,
		command,
		approvalID,
		expiresAt.UTC().Format(time.RFC3339),
		fingerprintPrefix,
	)
}
