package approval

import (
	"encoding/json"
	"sync"
	"time"
)

// sessionGrants remembers approved execute_remote payloads for the lifetime of
// luna serve so repeat calls skip Telegram until grant expiry (approval TTL).
type sessionGrants struct {
	mu      sync.RWMutex
	exact   map[string]time.Time // host + command + timeout
	command map[string]time.Time // command + timeout (any host)
}

func newSessionGrants() *sessionGrants {
	return &sessionGrants{
		exact:   make(map[string]time.Time),
		command: make(map[string]time.Time),
	}
}

func (g *sessionGrants) remember(exactKey, commandKey string, expiresAt time.Time) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.exact[exactKey] = expiresAt
	g.command[commandKey] = expiresAt
}

func (g *sessionGrants) allowed(exactKey, commandKey string, now time.Time) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(now)
	if exp, ok := g.exact[exactKey]; ok && now.Before(exp) {
		return true
	}
	if exp, ok := g.command[commandKey]; ok && now.Before(exp) {
		return true
	}
	return false
}

func (g *sessionGrants) pruneLocked(now time.Time) {
	for k, exp := range g.exact {
		if !now.Before(exp) {
			delete(g.exact, k)
		}
	}
	for k, exp := range g.command {
		if !now.Before(exp) {
			delete(g.command, k)
		}
	}
}

func commandGrantKey(s *Service, req ExecuteRemoteRequest) string {
	body, _ := json.Marshal(struct {
		Tool       string  `json:"tool"`
		Command    string  `json:"command"`
		TimeoutSec float64 `json:"timeout_sec"`
	}{
		Tool: req.Tool, Command: req.Command, TimeoutSec: req.TimeoutSec,
	})
	return s.bindingMAC(body)
}
