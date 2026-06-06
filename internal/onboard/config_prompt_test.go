package onboard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ba0f3/lunacli/internal/config"
)

func TestWriteConfigJSON_mergeOverlaysExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "luna.config.json")
	existing := `{
  "config_dir": "./luna.d",
  "telegram": {
    "approver_user_id": "111",
    "chat_id": "111"
  }
}
`
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	updates := config.FileSettings{
		Transport: config.TransportSettings{
			Mode: "proxy",
			Proxy: config.ProxyTransportSettings{
				Endpoint: "https://proxy.example:8443",
			},
		},
	}
	wrote, err := WriteConfigJSON(path, WriteMerge, updates)
	if err != nil || !wrote {
		t.Fatalf("WriteConfigJSON() wrote=%v err=%v", wrote, err)
	}

	fs, ok, err := ReadConfigJSON(path)
	if err != nil || !ok {
		t.Fatalf("ReadConfigJSON() ok=%v err=%v", ok, err)
	}
	if fs.ConfigDir != "./luna.d" {
		t.Fatalf("ConfigDir = %q", fs.ConfigDir)
	}
	if fs.Telegram.ApproverUserID != "111" {
		t.Fatalf("ApproverUserID = %q", fs.Telegram.ApproverUserID)
	}
	if fs.Transport.Proxy.Endpoint != "https://proxy.example:8443" {
		t.Fatalf("Endpoint = %q", fs.Transport.Proxy.Endpoint)
	}
}

func TestOverlayFileSettings_preservesExistingTelegram(t *testing.T) {
	base := config.FileSettings{
		Telegram: config.TelegramSettings{
			ApproverUserID: "111",
			ChatID:         "111",
		},
	}
	updates := config.FileSettings{
		Transport: config.TransportSettings{
			Mode: "proxy",
			Proxy: config.ProxyTransportSettings{
				Endpoint: "https://proxy.test",
			},
		},
	}
	out := OverlayFileSettings(base, updates)
	if out.Telegram.ApproverUserID != "111" {
		t.Fatalf("ApproverUserID = %q", out.Telegram.ApproverUserID)
	}
	if out.Transport.Proxy.Endpoint != "https://proxy.test" {
		t.Fatalf("Endpoint = %q", out.Transport.Proxy.Endpoint)
	}
}

func TestPromptTransport_keepExisting(t *testing.T) {
	in := strings.NewReader("1\n")
	var out, errOut bytes.Buffer
	p := NewPrompter(in, &out)

	existing := config.TransportSettings{
		Mode: "proxy",
		Proxy: config.ProxyTransportSettings{
			Endpoint: "https://proxy.example:8443",
		},
	}
	ts, err := PromptTransport(p, &out, &errOut, existing, true)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Proxy.Endpoint != existing.Proxy.Endpoint {
		t.Fatalf("Endpoint = %q, want keep", ts.Proxy.Endpoint)
	}
}

func TestPromptTelegram_keepExisting(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "telegram-bot-token")
	if err := os.WriteFile(tokenPath, []byte("secret-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	in := strings.NewReader("1\n")
	var out, errOut bytes.Buffer
	p := NewPrompter(in, &out)

	existing := config.TelegramSettings{
		BotTokenFile:   tokenPath,
		ApproverUserID: "52007861",
		ChatID:         "52007861",
	}
	ts, err := PromptTelegram(p, &out, &errOut, Layout{TokenFile: tokenPath}, existing, true)
	if err != nil {
		t.Fatal(err)
	}
	if ts.ApproverUserID != existing.ApproverUserID {
		t.Fatalf("ApproverUserID = %q", ts.ApproverUserID)
	}
}
