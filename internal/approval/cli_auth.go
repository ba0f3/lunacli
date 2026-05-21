package approval

import (
	"errors"
	"fmt"
	"strings"
)

// ErrCLIApproverForbidden is returned when the given uid cannot approve via the local approvals CLI.
var ErrCLIApproverForbidden = errors.New("uid not authorized for approvals CLI approve (configure cli.approver_users in config or LUNA_CLI_APPROVER_USERS)")

// AuthorizeCLIApprover returns nil if uid appears in allowedCSV (comma-separated trimmed entries).
func AuthorizeCLIApprover(uid, allowedCSV string) error {
	raw := strings.TrimSpace(allowedCSV)
	if raw == "" {
		return fmt.Errorf("%w: empty allow list", ErrCLIApproverForbidden)
	}
	for _, part := range strings.Split(raw, ",") {
		if strings.TrimSpace(part) == uid {
			return nil
		}
	}
	return fmt.Errorf("%w: uid %s not listed", ErrCLIApproverForbidden, uid)
}
