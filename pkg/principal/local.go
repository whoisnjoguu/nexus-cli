package principal

import (
	"context"
	"time"
)

// LocalProvider mints a principal from operator-supplied identity with no external IdP.
type LocalProvider struct {
	Subject string
	Email   string
	Scopes  []string
	TTL     time.Duration
}

// Name identifies the provider.
func (p LocalProvider) Name() string { return "local" }

// Login returns a principal built directly from the configured fields.
func (p LocalProvider) Login(_ context.Context) (*Principal, error) {
	subject := p.Subject
	if subject == "" {
		subject = p.Email
	}
	var exp time.Time
	if p.TTL > 0 {
		exp = time.Now().Add(p.TTL)
	}
	return &Principal{
		Subject:   subject,
		Email:     p.Email,
		Issuer:    "local",
		Scopes:    p.Scopes,
		ExpiresAt: exp,
	}, nil
}
