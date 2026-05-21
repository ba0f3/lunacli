package approval

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/ba0f3/lunacli/internal/config"
)

// ServeApproval wires in-memory approvals and a Telegram poll loop for luna serve.
type ServeApproval struct {
	Gate       *Gate
	PollCancel context.CancelFunc
}

// BootstrapServeApproval builds memory-backed approval state and starts Telegram polling.
func BootstrapServeApproval(settings *config.Settings) (*ServeApproval, error) {
	appCfg, err := LoadConfig(settings)
	if err != nil {
		return nil, err
	}

	store := NewMemoryStore()
	svc := NewService(store, appCfg)
	tg, err := RequireTelegramProvider(settings, svc)
	if err != nil {
		return nil, err
	}

	providers := NewProviderSet(tg)
	gate := NewGate(appCfg, svc, providers)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := tg.Poll(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("telegram poll: %v", err)
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = svc.ExpireDue()
			}
		}
	}()

	return &ServeApproval{Gate: gate, PollCancel: cancel}, nil
}
