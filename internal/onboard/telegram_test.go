package onboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverApprover_fromMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bottok/getUpdates" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"from":{"id":4242},"chat":{"id":9999},"text":"/start"}}]}`))
	}))
	defer srv.Close()

	approver, chat, err := DiscoverApprover(context.Background(), "tok", srv.Client(), srv.URL+"/bot%s/")
	if err != nil {
		t.Fatal(err)
	}
	if approver != "4242" || chat != "9999" {
		t.Fatalf("approver=%s chat=%s", approver, chat)
	}
}

func TestSaveBotToken_rejectsEmpty(t *testing.T) {
	if err := SaveBotToken(t.TempDir()+"/token", "  "); err == nil {
		t.Fatal("expected error")
	}
}
