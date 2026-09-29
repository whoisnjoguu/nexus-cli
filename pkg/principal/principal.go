// Package principal establishes the human identity (act_as) an agent operates on behalf of.
package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Principal is a verified human identity plus the scope ceiling it may delegate to agents.
type Principal struct {
	Subject   string    `json:"subject"` // stable ID, e.g. alice@company.com or oidc:sub
	Email     string    `json:"email"`   // human-readable email when available
	Issuer    string    `json:"issuer"`  // "local", or "nexus:<provider>" via the framework
	Scopes    []string  `json:"scopes"`  // maximum scopes this human can delegate
	ExpiresAt time.Time `json:"expires_at"`

	// GatewayURL and ConnectionID link this principal to its primary broker connection
	GatewayURL   string `json:"gateway_url,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`

	// Connections holds every broker connection the human has established
	Connections map[string]Connection `json:"connections,omitempty"`
}

// Connection is a single nexus-framework broker connection for one provider.
type Connection struct {
	Provider     string    `json:"provider"`
	ConnectionID string    `json:"connection_id"`
	GatewayURL   string    `json:"gateway_url"`
	Scopes       []string  `json:"scopes,omitempty"`
	Status       string    `json:"status,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// AddConnection records (or replaces) a provider connection on the principal.
func (p *Principal) AddConnection(c Connection) {
	if p.Connections == nil {
		p.Connections = make(map[string]Connection)
	}
	p.Connections[c.Provider] = c
}

// GetConnection returns the stored connection for a provider, if any.
func (p *Principal) GetConnection(provider string) (Connection, bool) {
	c, ok := p.Connections[provider]
	return c, ok
}

// Providers lists the providers the human has connected, sorted for stable output.
func (p *Principal) Providers() []string {
	out := make([]string, 0, len(p.Connections))
	for name := range p.Connections {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Valid reports whether the principal is present and unexpired.
func (p *Principal) Valid() bool {
	if p == nil || p.Subject == "" {
		return false
	}
	return p.ExpiresAt.IsZero() || time.Now().Before(p.ExpiresAt)
}

// CapScopes intersects requested scopes with the principal's ceiling
func (p *Principal) CapScopes(requested []string) []string {
	if len(p.Scopes) == 0 {
		return requested
	}
	allowed := make(map[string]bool, len(p.Scopes))
	for _, s := range p.Scopes {
		allowed[s] = true
	}
	var out []string
	for _, s := range requested {
		if allowed[s] {
			out = append(out, s)
		}
	}
	return out
}

// Provider authenticates a human and returns their verified principal.
type Provider interface {
	Name() string
	Login(ctx context.Context) (*Principal, error)
}

// DefaultSessionPath returns the cached-session location (~/.nexus/session.json).
func DefaultSessionPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus", "session.json"), nil
}

// Save persists the principal to disk with owner-only permissions.
func Save(path string, p *Principal) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return nil
}

// Load reads the cached principal, returning (nil, nil) if no session exists.
func Load(path string) (*Principal, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	var p Principal
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse session: %w", err)
	}
	return &p, nil
}

// Clear removes the cached session (logout).
func Clear(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
