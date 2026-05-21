package approval

import (
	"errors"
	"sync"
	"time"
)

var errInsertPendingRequiresPending = errors.New("InsertPending requires status pending")

// MemoryStore holds approval records in process memory for MCP-only mode.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]Record
}

// NewMemoryStore returns an empty in-memory approval store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record)}
}

func (m *MemoryStore) InsertPending(r Record) error {
	if r.Status != StatusPending {
		return errInsertPendingRequiresPending
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.records[r.ID]; exists {
		return ErrMismatch
	}
	m.records[r.ID] = r
	return nil
}

func (m *MemoryStore) Get(id string) (Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}

func (m *MemoryStore) ListPending() ([]Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Record
	for _, r := range m.records {
		if r.Status == StatusPending {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MemoryStore) UpdateStatus(id string, status Status, approver string, decidedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = status
	r.Approver = approver
	t := decidedAt.UTC()
	r.DecidedAt = &t
	m.records[id] = r
	return nil
}

func (m *MemoryStore) MarkConsumed(id string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.Status = StatusConsumed
	m.records[id] = r
	return nil
}

func (m *MemoryStore) AppendAudit(_ AuditEvent) error { return nil }

func (m *MemoryStore) ExpireDue(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now = now.UTC()
	for id, r := range m.records {
		if r.Status == StatusPending && now.After(r.ExpiresAt) {
			r.Status = StatusExpired
			t := now
			r.DecidedAt = &t
			m.records[id] = r
		}
	}
	return nil
}

func (m *MemoryStore) SetTelegramMessage(id string, chatID, messageID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[id]
	if !ok {
		return ErrNotFound
	}
	r.TelegramChatID = chatID
	r.TelegramMessageID = messageID
	m.records[id] = r
	return nil
}

func (m *MemoryStore) Close() error { return nil }
