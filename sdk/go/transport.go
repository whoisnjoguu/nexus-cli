package sdk

import (
	"context"
	"fmt"
	"net/http"
)

// TokenSource supplies a fresh dual-actor bearer token for outbound requests.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// GateTransport wraps an http.RoundTripper so every request is authorized by a Gate before it
// leaves the process, and stamped with a dual-actor bearer token. This is the drop-in path for
// agents that make HTTP tool calls: set it as the client's Transport and tool calls are gated.
type GateTransport struct {
	Base   http.RoundTripper
	Gate   Gate
	Tokens TokenSource
	Agent  string
	ActAs  string
	// Session groups related calls for taint tracking; defaults to Agent when empty.
	Session string
	// Scopes advertises the caller's granted scopes to the gate.
	Scopes []string
}

// RoundTrip authorizes the request, attaches the bearer token, and forwards it on success.
func (t *GateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.Gate != nil {
		session := t.Session
		if session == "" {
			session = t.Agent
		}
		dec, err := t.Gate.Authorize(req.Context(), ToolCall{
			SessionID: session,
			Agent:     t.Agent,
			ActAs:     t.ActAs,
			Method:    req.Method,
			Host:      req.URL.Host,
			Path:      req.URL.Path,
			Scopes:    t.Scopes,
		})
		if err != nil {
			return nil, err
		}
		if !dec.Allowed {
			return nil, fmt.Errorf("nexus: tool call denied: %s", dec.Reason)
		}
	}
	if t.Tokens != nil {
		tok, err := t.Tokens.Token(req.Context())
		if err != nil {
			return nil, fmt.Errorf("nexus: token: %w", err)
		}
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return base.RoundTrip(req)
}
