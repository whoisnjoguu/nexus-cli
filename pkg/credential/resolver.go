// Package credential resolves short-lived upstream credentials from the nexus-framework broker,
// so the proxy can inject them into allowed requests and agents never hold a durable secret.
package credential

import (
	"context"
	"fmt"
	"sync"
	"time"

	oauthsdk "github.com/Prescott-Data/nexus-framework/nexus-sdk"
)

// Resolver fetches access tokens for a broker connection, caching Gateway clients per URL.
type Resolver struct {
	mu      sync.Mutex
	clients map[string]*oauthsdk.Client
	timeout time.Duration
}

// NewResolver builds a credential resolver.
func NewResolver() *Resolver {
	return &Resolver{clients: make(map[string]*oauthsdk.Client), timeout: 15 * time.Second}
}

// Token returns a fresh access token for the given Gateway + connection.
func (r *Resolver) Token(ctx context.Context, gatewayURL, connectionID string) (string, error) {
	if gatewayURL == "" || connectionID == "" {
		return "", fmt.Errorf("credential: gateway and connection id are required")
	}
	client := r.clientFor(gatewayURL)

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	tok, err := client.GetToken(ctx, connectionID)
	if err != nil {
		return "", fmt.Errorf("credential: fetch token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("credential: broker returned empty token")
	}
	return tok.AccessToken, nil
}

func (r *Resolver) clientFor(gatewayURL string) *oauthsdk.Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[gatewayURL]; ok {
		return c
	}
	c := oauthsdk.New(gatewayURL)
	r.clients[gatewayURL] = c
	return c
}
