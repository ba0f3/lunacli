package approval

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestTelegramProvider_Poll_ApproveCallback(t *testing.T) {
	const token = "poll-token"
	var answerCalled atomic.Bool
	var getUpdatesCalls atomic.Int32

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
	pending, err := svc.CreatePending(executeRemoteToolName, req, body, fp, "mutating", "policy")
	if err != nil {
		t.Fatalf("CreatePending() error = %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bot" + token + "/getUpdates":
			w.Header().Set("Content-Type", "application/json")
			if getUpdatesCalls.Add(1) == 1 {
				_, _ = w.Write([]byte(`{
					"ok": true,
					"result": [{
						"update_id": 42,
						"callback_query": {
							"id": "cb-1",
							"from": {"id": 111},
							"data": "approve:` + pending.ID + `"
						}
					}]
				}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		case "/bot" + token + "/answerCallbackQuery":
			answerCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			body, _ := io.ReadAll(r.Body)
			t.Fatalf("unexpected path %s body %s", r.URL.Path, string(body))
		}
	}))
	t.Cleanup(srv.Close)

	tg, err := NewTelegramProvider(svc, TelegramProviderOptions{
		BotToken:       token,
		ApproverUserID: "111",
		ChatID:         "111",
		APIBaseURL:     srv.URL,
	})
	if err != nil {
		t.Fatalf("NewTelegramProvider() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tg.Poll(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rec, err := svc.Get(pending.ID)
		if err == nil && rec.Status == StatusApproved {
			cancel()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-done

	rec, err := svc.Get(pending.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if rec.Status != StatusApproved {
		t.Fatalf("status = %q, want approved", rec.Status)
	}
	if !answerCalled.Load() {
		t.Fatal("expected answerCallbackQuery to be called")
	}
}

func TestTelegramProvider_Poll_GetUpdatesRequestShape(t *testing.T) {
	const token = "shape-token"
	var captured []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+token+"/getUpdates" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
	}))
	t.Cleanup(srv.Close)

	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "approvals.db"))
	if err != nil {
		t.Fatalf("OpenSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc := NewService(store, Config{TTL: time.Minute})
	tg, err := NewTelegramProvider(svc, TelegramProviderOptions{
		BotToken:       token,
		ApproverUserID: "1",
		APIBaseURL:     srv.URL,
	})
	if err != nil {
		t.Fatalf("NewTelegramProvider() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tg.Poll(ctx)

	var req telegramGetUpdatesRequest
	if err := json.Unmarshal(captured, &req); err != nil {
		t.Fatalf("decode getUpdates body: %v", err)
	}
	if req.Timeout != telegramLongPollSec {
		t.Fatalf("timeout = %d, want %d", req.Timeout, telegramLongPollSec)
	}
	if len(req.AllowedUpdates) != 1 || req.AllowedUpdates[0] != "callback_query" {
		t.Fatalf("allowed_updates = %v", req.AllowedUpdates)
	}
}
