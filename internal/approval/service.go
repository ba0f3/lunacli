package approval

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrConsumed = errors.New("approval already consumed")
	ErrExpired  = errors.New("approval expired")
	ErrDenied   = errors.New("approval denied")
	ErrMismatch = errors.New("approval request mismatch")
)

// PendingInfo is returned when a mutating request is waiting for human approval.
type PendingInfo struct {
	ID                string
	Fingerprint       string
	FingerprintPrefix string
	ExpiresAt         time.Time
}

// Service coordinates approval lifecycle transitions on top of a Store.
type Service struct {
	store Store
	cfg   Config
	now   func() time.Time
}

// NewService returns an approval service using cfg.TTL for pending expiry.
// The clock defaults to time.Now; tests in this package may replace svc.now.
func NewService(store Store, cfg Config) *Service {
	return &Service{
		store: store,
		cfg:   cfg,
		now:   time.Now,
	}
}

// CreatePending inserts a pending approval and records request_created audit.
func (s *Service) CreatePending(tool string, req ExecuteRemoteRequest, body []byte, fingerprint, class, reason string) (PendingInfo, error) {
	if s.cfg.TTL <= 0 {
		return PendingInfo{}, fmt.Errorf("approval TTL must be positive")
	}
	id := uuid.NewString()
	now := s.now().UTC()
	expires := now.Add(s.cfg.TTL)

	bodyCopy := append([]byte(nil), body...)
	rec := Record{
		ID:               id,
		Tool:             tool,
		Host:             req.Host,
		RedactedCommand:  req.Command,
		NormalizedBody:   bodyCopy,
		Classification:   class,
		Reason:           reason,
		Fingerprint:      fingerprint,
		Status:           StatusPending,
		CreatedAt:        now,
		ExpiresAt:        expires,
		Approver:         "",
		RedactionVersion: RedactionVersion,
	}
	if err := s.store.InsertPending(rec); err != nil {
		return PendingInfo{}, err
	}
	detail := fmt.Sprintf(`{"tool":%q,"fingerprint_prefix":%q}`, tool, FingerprintPrefix(fingerprint))
	if err := s.store.AppendAudit(AuditEvent{
		ApprovalID: id,
		EventType:  "request_created",
		Detail:     detail,
		CreatedAt:  now,
	}); err != nil {
		return PendingInfo{}, err
	}
	return PendingInfo{
		ID:                id,
		Fingerprint:       fingerprint,
		FingerprintPrefix: FingerprintPrefix(fingerprint),
		ExpiresAt:         expires,
	}, nil
}

// Approve transitions pending → approved. Expired pendings become expired and return ErrExpired.
func (s *Service) Approve(id, approver, provider string) error {
	r, err := s.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return err
	}

	switch r.Status {
	case StatusConsumed:
		return ErrConsumed
	case StatusDenied:
		return ErrDenied
	case StatusExpired:
		return ErrExpired
	case StatusApproved:
		return ErrMismatch
	case StatusPending:
	default:
		return ErrMismatch
	}

	now := s.now().UTC()
	if now.After(r.ExpiresAt) {
		if err := s.store.UpdateStatus(id, StatusExpired, "", now); err != nil {
			return err
		}
		detail := `{"reason":"expired_before_decision"}`
		_ = s.store.AppendAudit(AuditEvent{
			ApprovalID: id,
			EventType:  "expired",
			Detail:     detail,
			CreatedAt:  now,
		})
		return ErrExpired
	}

	if err := s.store.UpdateStatus(id, StatusApproved, approver, now); err != nil {
		return err
	}
	detail := fmt.Sprintf(`{"approver":%q,"provider":%q}`, approver, provider)
	return s.store.AppendAudit(AuditEvent{
		ApprovalID: id,
		EventType:  "approved",
		Detail:     detail,
		CreatedAt:  now,
	})
}

// Deny transitions pending → denied.
func (s *Service) Deny(id, approver, provider string) error {
	r, err := s.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return err
	}

	switch r.Status {
	case StatusConsumed:
		return ErrConsumed
	case StatusDenied:
		return ErrDenied
	case StatusExpired:
		return ErrExpired
	case StatusApproved:
		return ErrMismatch
	case StatusPending:
	default:
		return ErrMismatch
	}

	now := s.now().UTC()
	if now.After(r.ExpiresAt) {
		if err := s.store.UpdateStatus(id, StatusExpired, "", now); err != nil {
			return err
		}
		return ErrExpired
	}

	if err := s.store.UpdateStatus(id, StatusDenied, approver, now); err != nil {
		return err
	}
	detail := fmt.Sprintf(`{"approver":%q,"provider":%q}`, approver, provider)
	return s.store.AppendAudit(AuditEvent{
		ApprovalID: id,
		EventType:  "denied",
		Detail:     detail,
		CreatedAt:  now,
	})
}

// VerifyAndConsume checks an approved, non-expired request matches the payload and fingerprint, then marks it consumed.
func (s *Service) VerifyAndConsume(id string, req ExecuteRemoteRequest, body []byte, fingerprint string) error {
	r, err := s.store.Get(id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return err
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

	if len(fingerprint) != len(r.Fingerprint) || subtle.ConstantTimeCompare([]byte(fingerprint), []byte(r.Fingerprint)) != 1 {
		return ErrMismatch
	}
	if ComputeFingerprint(body) != fingerprint {
		return ErrMismatch
	}
	if !bytes.Equal(body, r.NormalizedBody) {
		return ErrMismatch
	}
	if req.Tool != r.Tool || req.Host != r.Host || req.Command != r.RedactedCommand {
		return ErrMismatch
	}

	if err := s.store.MarkConsumed(id, now); err != nil {
		return err
	}
	return s.store.AppendAudit(AuditEvent{
		ApprovalID: id,
		EventType:  "consumed",
		Detail:     `{"via":"verify_and_consume"}`,
		CreatedAt:  now,
	})
}

// ExpireDue marks overdue pending approvals as expired (decided_at = now).
func (s *Service) ExpireDue() error {
	return s.store.ExpireDue(s.now())
}

// Get loads a persisted approval record by id.
func (s *Service) Get(id string) (Record, error) {
	return s.store.Get(id)
}

// ListPending returns all approvals in pending status, oldest created first.
func (s *Service) ListPending() ([]Record, error) {
	return s.store.ListPending()
}

// SetTelegramMessage records the Telegram chat/message ids for a pending approval prompt.
func (s *Service) SetTelegramMessage(id string, chatID, messageID int64) error {
	if chatID == 0 || messageID == 0 {
		return nil
	}
	return s.store.SetTelegramMessage(id, chatID, messageID)
}

// AppendAudit records an audit event. If ev.CreatedAt is zero, svc.now() is used.
func (s *Service) AppendAudit(ev AuditEvent) error {
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = s.now().UTC()
	} else {
		ev.CreatedAt = ev.CreatedAt.UTC()
	}
	return s.store.AppendAudit(ev)
}
