package onboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverApprover(t *testing.T) {
	tests := []struct {
		name             string
		setupServer      func(t *testing.T) (*httptest.Server, string)
		expectError      bool
		expectedApprover string
		expectedChat     string
	}{
		{
			name: "fromMessage",
			setupServer: func(t *testing.T) (*httptest.Server, string) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/bottok/getUpdates" {
						http.NotFound(w, r)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"from":{"id":4242},"chat":{"id":9999},"text":"/start"}}]}`))
				}))
				return srv, "tok"
			},
			expectError:      false,
			expectedApprover: "4242",
			expectedChat:     "9999",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, token := tc.setupServer(t)
			defer srv.Close()

			approver, chat, err := DiscoverApprover(context.Background(), token, srv.Client(), srv.URL+"/bot%s/")
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if approver != tc.expectedApprover || chat != tc.expectedChat {
					t.Fatalf("approver=%s chat=%s, want approver=%s chat=%s", approver, chat, tc.expectedApprover, tc.expectedChat)
				}
			}
		})
	}
}

func TestSaveBotToken(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "rejectsEmpty",
			token:       "  ",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := t.TempDir() + "/token"
			err := SaveBotToken(path, tc.token)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
