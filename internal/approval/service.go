package approval

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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
	store      Store
	cfg        Config
	now        func() time.Time
	bindingKey []byte
	grants     *sessionGrants
}

// NewService returns an approval service using cfg.TTL for pending expiry.
// The clock defaults to time.Now; tests in this package may replace svc.now.
func NewService(store Store, cfg Config) *Service {
	bindingKey := make([]byte, 32)
	if _, err := rand.Read(bindingKey); err != nil {
		panic(fmt.Sprintf("generate approval binding key: %v", err))
	}
	return &Service{
		store:      store,
		cfg:        cfg,
		now:        time.Now,
		bindingKey: bindingKey,
		grants:     newSessionGrants(),
	}
}

// RememberSessionGrant records an approved execute_remote for in-process reuse
// until the approval TTL elapses. Grants match the exact host+command and the
// same command on any host (fleet diagnostics).
func (s *Service) RememberSessionGrant(req ExecuteRemoteRequest) {
	if s == nil || s.grants == nil || s.cfg.TTL <= 0 {
		return
	}
	expires := s.now().UTC().Add(s.cfg.TTL)
	s.grants.remember(s.exactBinding(req), commandGrantKey(s, req), expires)
}

// HasSessionGrant reports whether req was approved earlier in this process and
// the grant has not expired.
func (s *Service) HasSessionGrant(req ExecuteRemoteRequest) bool {
	if s == nil || s.grants == nil {
		return false
	}
	now := s.now().UTC()
	return s.grants.allowed(s.exactBinding(req), commandGrantKey(s, req), now)
}

// CreatePending inserts a pending approval and records request_created audit.
func (s *Service) CreatePending(tool string, req ExecuteRemoteRequest, body []byte, fingerprint, class, reason string) (PendingInfo, error) {
	return s.createPending(tool, req.Host, req.Command, body, fingerprint, class, reason, s.exactBinding(req))
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
	if !hmac.Equal([]byte(s.exactBinding(req)), []byte(r.ExactBinding)) {
		return ErrMismatch
	}

	if err := s.store.ConsumeApproved(id, now); err != nil {
		return err
	}
	return s.store.AppendAudit(AuditEvent{
		ApprovalID: id,
		EventType:  "consumed",
		Detail:     `{"via":"verify_and_consume"}`,
		CreatedAt:  now,
	})
}

func (s *Service) exactBinding(req ExecuteRemoteRequest) string {
	command := req.rawCommand
	if command == "" {
		command = req.Command
	}
	body, _ := json.Marshal(struct {
		Tool       string  `json:"tool"`
		Host       string  `json:"host"`
		Command    string  `json:"command"`
		TimeoutSec float64 `json:"timeout_sec"`
	}{
		Tool: req.Tool, Host: req.Host, Command: command, TimeoutSec: req.TimeoutSec,
	})
	return s.bindingMAC(body)
}

func (s *Service) bindingMAC(body []byte) string {
	mac := hmac.New(sha256.New, s.bindingKey)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) createPending(tool, host, summary string, body []byte, fingerprint, class, reason, exactBinding string) (PendingInfo, error) {
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
		Host:             host,
		RedactedCommand:  summary,
		NormalizedBody:   bodyCopy,
		Classification:   class,
		Reason:           reason,
		Fingerprint:      fingerprint,
		ExactBinding:     exactBinding,
		Status:           StatusPending,
		CreatedAt:        now,
		ExpiresAt:        expires,
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
