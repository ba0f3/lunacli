package approval

import (
	"errors"
	"time"
)

// ErrNotFound is returned when an approval ID does not exist in the store.
var ErrNotFound = errors.New("approval not found")

// Status is persisted approval lifecycle state.
type Status string

type Record struct {
	ID                string
	Tool              string
	Host              string
	RedactedCommand   string
	NormalizedBody    []byte
	Classification    string
	Reason            string
	Fingerprint       string
	Status            Status
	CreatedAt         time.Time
	ExpiresAt         time.Time
	DecidedAt         *time.Time
	Approver          string
	RedactionVersion  string
	TelegramChatID    int64
	TelegramMessageID int64
}

type AuditEvent struct {
	ApprovalID string
	EventType  string
	Detail     string
	CreatedAt  time.Time
}

type Store interface {
	InsertPending(r Record) error
	Get(id string) (Record, error)
	ListPending() ([]Record, error)
	UpdateStatus(id string, status Status, approver string, decidedAt time.Time) error
	MarkConsumed(id string, at time.Time) error
	AppendAudit(e AuditEvent) error
	ExpireDue(now time.Time) error
	SetTelegramMessage(id string, chatID, messageID int64) error
	Close() error
}
