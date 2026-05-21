package approval

import (
	"strings"
	"testing"
	"time"
)

func TestFormatTelegramPendingMessage_HTML(t *testing.T) {
	text := formatTelegramPendingMessage(PendingInfo{
		ID:                "id-1",
		FingerprintPrefix: "abcd1234",
		ExpiresAt:         time.Date(2026, 5, 21, 17, 6, 2, 0, time.UTC),
	}, ExecuteRemoteRequest{
		Host:    "ubuntu@10.9.5.51",
		Command: "echo 'a' > /tmp & test",
	})
	if !strings.Contains(text, "<b>🌙 Luna</b>") {
		t.Fatalf("missing header: %s", text)
	}
	if !strings.Contains(text, "<pre>echo 'a' &gt; /tmp &amp; test</pre>") {
		t.Fatalf("command not escaped in pre: %s", text)
	}
	if strings.Contains(text, "ubuntu@10.9.5.51</code>") && strings.Contains(text, "<code>ubuntu@10.9.5.51</code>") {
		// host in code block avoids spurious link styling
	}
}

func TestFormatTelegramResolvedMessage_Approved(t *testing.T) {
	text := formatTelegramResolvedMessage(Record{
		ID:              "id-2",
		Host:            "web1",
		RedactedCommand: "uptime",
	}, "APPROVED", "via cli · 1000")
	if !strings.Contains(text, "✅") || !strings.Contains(text, "<b>APPROVED</b>") {
		t.Fatalf("missing approved styling: %s", text)
	}
	if !strings.Contains(text, "<i>via cli · 1000</i>") {
		t.Fatalf("missing detail: %s", text)
	}
	if strings.Contains(text, "id-2") {
		t.Fatalf("resolved message should not repeat full request id: %s", text)
	}
}

func TestTruncateTelegramCommand(t *testing.T) {
	long := strings.Repeat("a", 300)
	got := truncateTelegramCommand(long)
	if len([]rune(got)) > telegramMaxCommandRunes {
		t.Fatalf("truncated len = %d, max %d", len([]rune(got)), telegramMaxCommandRunes)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("expected ellipsis suffix, got %q", got)
	}
}
