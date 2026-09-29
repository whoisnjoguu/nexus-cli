package jwt

import (
	"fmt"
	"sync"
	"time"
)

// ReplayGuard rejects reuse of a token ID (jti) within its validity window
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry
}

// NewReplayGuard builds an empty replay guard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: make(map[string]time.Time)}
}

// Use records a jti as consumed until expiry
func (g *ReplayGuard) Use(jti string, expiry time.Time) error {
	if jti == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	for id, exp := range g.seen {
		if now.After(exp) {
			delete(g.seen, id)
		}
	}
	if exp, ok := g.seen[jti]; ok && now.Before(exp) {
		return fmt.Errorf("token replay detected for jti %s", jti)
	}
	g.seen[jti] = expiry
	return nil
}
