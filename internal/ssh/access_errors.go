package ssh

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrAccessRequired indicates proxy access approval is still pending.
	ErrAccessRequired = errors.New("access required")
	// ErrAccessDenied indicates proxy access was denied.
	ErrAccessDenied = errors.New("access denied")
	// ErrAccessExpired indicates signed credentials expired.
	ErrAccessExpired = errors.New("access expired")
)

// FormatAccessError returns MCP-safe ACCESS_* prefixed text for a target.
func FormatAccessError(t Target, err error) string {
	raw := strings.TrimSpace(t.Raw)
	if raw == "" {
		raw = fmt.Sprintf("%s@%s:%s", t.User, t.Host, t.Port)
	}
	switch {
	case errors.Is(err, ErrAccessRequired):
		return fmt.Sprintf("ACCESS_REQUIRED: %s — approve access on luna-proxy Telegram, then retry", raw)
	case errors.Is(err, ErrAccessDenied):
		return fmt.Sprintf("ACCESS_DENIED: %s — access denied on luna-proxy", raw)
	case errors.Is(err, ErrAccessExpired):
		return fmt.Sprintf("ACCESS_EXPIRED: %s — re-approve access on luna-proxy", raw)
	default:
		return fmt.Sprintf("ACCESS_DENIED: %s — %v", raw, err)
	}
}

// AccessErrorMessage returns formatted ACCESS_* text if err is an access error.
func AccessErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var t Target
	if errors.Is(err, ErrAccessRequired) || errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrAccessExpired) {
		return FormatAccessError(t, err)
	}
	msg := err.Error()
	for _, prefix := range []string{"ACCESS_REQUIRED:", "ACCESS_DENIED:", "ACCESS_EXPIRED:"} {
		if idx := strings.Index(msg, prefix); idx >= 0 {
			return strings.TrimSpace(msg[idx:])
		}
	}
	return ""
}
