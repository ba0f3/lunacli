package approval

import (
	"context"
	"time"
)

const approvalPollInterval = 1 * time.Second

// WaitForDecision polls until the approval leaves pending state or ctx is cancelled.
// Returns StatusApproved on success. ErrDenied, ErrExpired, and ErrConsumed reflect
// terminal non-success outcomes. Other errors include store failures and ctx.Err().
func (s *Service) WaitForDecision(ctx context.Context, id string) (Status, error) {
	ticker := time.NewTicker(approvalPollInterval)
	defer ticker.Stop()

	for {
		_ = s.ExpireDue()

		r, err := s.store.Get(id)
		if err != nil {
			return "", err
		}

		switch r.Status {
		case StatusApproved:
			return StatusApproved, nil
		case StatusDenied:
			return StatusDenied, ErrDenied
		case StatusExpired:
			return StatusExpired, ErrExpired
		case StatusConsumed:
			return StatusConsumed, ErrConsumed
		case StatusPending:
		default:
			return r.Status, ErrMismatch
		}

		select {
		case <-ctx.Done():
			return StatusPending, ctx.Err()
		case <-ticker.C:
		}
	}
}
