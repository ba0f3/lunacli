package approval

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryStore_PendingApproveConsume(t *testing.T) {
	st := NewMemoryStore()
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	rec := Record{
		ID: "id-1", Tool: executeRemoteToolName, Host: "h", RedactedCommand: "touch /tmp/x",
		NormalizedBody: []byte(`{}`), Classification: "mutating", Reason: "r",
		Fingerprint: "fp", Status: StatusPending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), RedactionVersion: RedactionVersion,
	}
	if err := st.InsertPending(rec); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateStatus("id-1", StatusApproved, "human", now); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("id-1")
	if err != nil || got.Status != StatusApproved {
		t.Fatalf("Get() = %+v, %v", got, err)
	}
	if err := st.MarkConsumed("id-1", now); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get("id-1")
	if err != nil || got.Status != StatusConsumed {
		t.Fatalf("after consume: %+v, %v", got, err)
	}
}

func TestMemoryStore_ExpireDue(t *testing.T) {
	st := NewMemoryStore()
	past := time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)
	rec := Record{
		ID: "exp-1", Tool: executeRemoteToolName, Host: "h", RedactedCommand: "x",
		NormalizedBody: []byte(`{}`), Classification: "mutating", Reason: "r",
		Fingerprint: "fp", Status: StatusPending,
		CreatedAt: past, ExpiresAt: past.Add(time.Second), RedactionVersion: RedactionVersion,
	}
	if err := st.InsertPending(rec); err != nil {
		t.Fatal(err)
	}
	now := past.Add(2 * time.Second)
	if err := st.ExpireDue(now); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("exp-1")
	if err != nil || got.Status != StatusExpired {
		t.Fatalf("status = %q, err = %v", got.Status, err)
	}
}

func TestMemoryStore_SetTelegramMessage(t *testing.T) {
	st := NewMemoryStore()
	now := time.Now().UTC()
	rec := Record{
		ID: "tg-1", Tool: executeRemoteToolName, Host: "h", RedactedCommand: "x",
		NormalizedBody: []byte(`{}`), Classification: "mutating", Reason: "r",
		Fingerprint: "fp", Status: StatusPending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), RedactionVersion: RedactionVersion,
	}
	if err := st.InsertPending(rec); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTelegramMessage("tg-1", 222, 99); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("tg-1")
	if err != nil || got.TelegramChatID != 222 || got.TelegramMessageID != 99 {
		t.Fatalf("telegram ids = %d/%d", got.TelegramChatID, got.TelegramMessageID)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	st := NewMemoryStore()
	_, err := st.Get("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
