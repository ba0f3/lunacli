package approval

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestService_SetTelegramMessage(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	req, body, fp, err := BuildExecuteRemoteRequest("h", "true", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	info, err := svc.CreatePending(executeRemoteToolName, req, body, fp, "mutating", "x")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := svc.SetTelegramMessage(info.ID, 222, 99); err != nil {
		t.Fatalf("SetTelegramMessage() error = %v", err)
	}
	rec, err := svc.Get(info.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if rec.TelegramChatID != 222 || rec.TelegramMessageID != 99 {
		t.Fatalf("stored ids = %d/%d, want 222/99", rec.TelegramChatID, rec.TelegramMessageID)
	}
}

func TestService_UpdateTelegramMessage_NoIDsNoOp(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	req, body, fp, err := BuildExecuteRemoteRequest("h", "true", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	info, err := svc.CreatePending(executeRemoteToolName, req, body, fp, "mutating", "x")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := svc.UpdateTelegramMessage(nil, info.ID); err != nil {
		t.Fatalf("UpdateTelegramMessage() error = %v, want nil", err)
	}
}

func TestTelegramProvider_EditResolvedAfterApprove(t *testing.T) {
	const token = "sync-token"
	var editBody []byte

	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	req, body, fp, err := BuildExecuteRemoteRequest("web1", "touch /tmp/x", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	info, err := svc.CreatePending(executeRemoteToolName, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}
	if err := svc.SetTelegramMessage(info.ID, 222, 99); err != nil {
		t.Fatalf("SetTelegramMessage() error = %v", err)
	}
	if err := svc.Approve(info.ID, "1000", "cli"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+token+"/editMessageText" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		editBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	tg, err := NewTelegramProvider(svc, TelegramProviderOptions{
		BotToken:       token,
		ApproverUserID: "111",
		APIBaseURL:     srv.URL,
	})
	if err != nil {
		t.Fatalf("NewTelegramProvider() error = %v", err)
	}

	rec, err := svc.Get(info.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	text := formatTelegramResolvedMessage(rec, "APPROVED", telegramResolvedDetailForProvider(rec, "1000", "cli", nil))
	if err := tg.editApprovalMessage(context.Background(), rec.TelegramChatID, rec.TelegramMessageID, text); err != nil {
		t.Fatalf("editApprovalMessage() error = %v", err)
	}
	bodyStr := string(editBody)
	if !strings.Contains(bodyStr, "APPROVED") || !strings.Contains(bodyStr, "via cli") {
		t.Fatalf("edit body = %s", bodyStr)
	}
}
