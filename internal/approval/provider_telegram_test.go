package approval

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTelegramProvider_Notify_SendMessageCallbackData(t *testing.T) {
	const token = "test-token"

	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/bot" + token + "/sendMessage"
		if r.URL.Path != wantPath {
			t.Errorf("request path = %q, want %q", r.URL.Path, wantPath)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		captured = body

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	tg, err := NewTelegramProvider(svc, TelegramProviderOptions{
		BotToken:       token,
		ApproverUserID: "111",
		ChatID:         "222",
		APIBaseURL:     srv.URL,
	})
	if err != nil {
		t.Fatalf("NewTelegramProvider() error = %v", err)
	}

	req := ExecuteRemoteRequest{Tool: executeRemoteToolName, Host: "web1", Command: "uptime", TimeoutSec: 30}
	pending := PendingInfo{
		ID:                "apr-test-notify",
		FingerprintPrefix: "abcd1234",
		ExpiresAt:         time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
	}
	if err := tg.Notify(pending, req); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}

	var msg telegramSendMessageBody
	if err := json.Unmarshal(captured, &msg); err != nil {
		t.Fatalf("decode captured JSON: %v", err)
	}
	if msg.ChatID != "222" {
		t.Fatalf("chat_id = %q, want 222", msg.ChatID)
	}
	if msg.ReplyMarkup == nil || len(msg.ReplyMarkup.InlineKeyboard) != 1 || len(msg.ReplyMarkup.InlineKeyboard[0]) != 2 {
		t.Fatalf("inline keyboard missing or malformed: %+v", msg.ReplyMarkup)
	}
	btn0 := msg.ReplyMarkup.InlineKeyboard[0][0]
	btn1 := msg.ReplyMarkup.InlineKeyboard[0][1]
	if btn0.CallbackData != "approve:apr-test-notify" {
		t.Fatalf("approve callback_data = %q", btn0.CallbackData)
	}
	if btn1.CallbackData != "deny:apr-test-notify" {
		t.Fatalf("deny callback_data = %q", btn1.CallbackData)
	}
	if want := "Approve"; btn0.Text != want {
		t.Fatalf("approve button text = %q, want %q", btn0.Text, want)
	}
	if want := "Deny"; btn1.Text != want {
		t.Fatalf("deny button text = %q, want %q", btn1.Text, want)
	}
}

func TestTelegramProvider_HandleCallback_UnauthorizedAudited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := OpenSQLiteStore(path)
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	tg, err := NewTelegramProvider(svc, TelegramProviderOptions{
		BotToken:       "tok",
		ApproverUserID: "111",
		ChatID:         "111",
	})
	if err != nil {
		t.Fatalf("NewTelegramProvider() error = %v", err)
	}

	req, body, fp, err := BuildExecuteRemoteRequest("web1", "echo hello", 30)
	if err != nil {
		t.Fatalf("BuildExecuteRemoteRequest() error = %v", err)
	}
	pending, err := svc.CreatePending(executeRemoteToolName, req, body, fp, "mutating", "echo")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}

	err = tg.HandleCallback("999", "approve:"+pending.ID)
	if !errors.Is(err, ErrTelegramCallbackUnauthorized) {
		t.Fatalf("HandleCallback() error = %v, want %v", err, ErrTelegramCallbackUnauthorized)
	}

	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	row := db.QueryRow(`
SELECT event_type, detail FROM audit_events WHERE approval_id = ? ORDER BY id DESC LIMIT 1
`, pending.ID)
	var etype, detail string
	if scanErr := row.Scan(&etype, &detail); scanErr != nil {
		t.Fatalf("scan audit: %v", scanErr)
	}
	if etype != "telegram_callback_unauthorized" {
		t.Fatalf("event_type = %q", etype)
	}
	if !strings.Contains(detail, `"telegram_user_id":"999"`) {
		t.Fatalf("detail = %q", detail)
	}
}
