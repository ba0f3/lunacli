package approval

import (
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

func TestBootstrapServeApproval_RequiresTelegram(t *testing.T) {
	settings := &config.Settings{}
	_, err := BootstrapServeApproval(settings)
	if err == nil {
		t.Fatal("expected error without telegram config")
	}
	if !strings.Contains(err.Error(), "telegram required") {
		t.Fatalf("error = %v", err)
	}
}

func TestRequireTelegramProvider_MissingConfig(t *testing.T) {
	svc := NewService(NewMemoryStore(), Config{TTL: time.Minute})
	settings := &config.Settings{}
	_, err := RequireTelegramProvider(settings, svc)
	if err == nil {
		t.Fatal("expected error")
	}
}
