package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

// brokerReady reports whether broker-access tools can run (a Gateway is configured).
func (s *Server) brokerReady() bool { return s.gateway != "" }

func (s *Server) ensureSession() *principal.Principal {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if s.session == nil {
		s.session = &principal.Principal{Subject: s.actAs}
	}
	return s.session
}

func (s *Server) saveSession() {
	if s.sessionPath == "" {
		return
	}
	s.sessionMu.Lock()
	sess := s.session
	s.sessionMu.Unlock()
	if sess != nil {
		_ = principal.Save(s.sessionPath, sess)
	}
}

func (s *Server) callListProviders() map[string]any {
	if !s.brokerReady() {
		return textResult(true, "broker access not configured (no Gateway URL)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	providers, err := principal.ListProviders(ctx, s.gateway)
	if err != nil {
		return textResult(true, "list providers failed: "+err.Error())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Providers available on the Gateway (%d):\n", len(providers))
	for _, p := range providers {
		fmt.Fprintf(&b, "- %s [%s] — %s\n", p.Name, p.AuthType, p.Category)
	}
	return textResult(false, b.String())
}

func (s *Server) callListConnections() map[string]any {
	s.sessionMu.Lock()
	sess := s.session
	s.sessionMu.Unlock()
	if sess == nil || len(sess.Connections) == 0 {
		return textResult(false, "No provider connections yet. Use request_access to add one.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var b strings.Builder
	b.WriteString("Provider connections:\n")
	for _, name := range sess.Providers() {
		c := sess.Connections[name]
		status := c.Status
		if s.brokerReady() {
			if st, err := principal.CheckStatus(ctx, c.GatewayURL, c.ConnectionID); err == nil {
				status = st
			}
		}
		active := "pending"
		if principal.IsActiveStatus(status) {
			active = "active"
		}
		fmt.Fprintf(&b, "- %s: %s (%s)\n", name, active, c.ConnectionID)
	}
	return textResult(false, b.String())
}

func (s *Server) callRequestAccess(args json.RawMessage) map[string]any {
	if !s.brokerReady() {
		return textResult(true, "broker access not configured (no Gateway URL)")
	}
	var a struct {
		Provider string   `json:"provider"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.Unmarshal(args, &a); err != nil || a.Provider == "" {
		return textResult(true, "provider is required")
	}

	userID := s.actAs
	if sess := s.session; sess != nil && sess.Subject != "" {
		userID = sess.Subject
	}

	// Prefer the scopes configured for this provider in the policy (TUI-managed) when the agent
	// didn't request specific ones.
	scopes := a.Scopes
	if len(scopes) == 0 && s.engine != nil {
		scopes = s.engine.ProviderScopes(a.Provider)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pending, err := principal.StartConnection(ctx, principal.ConnectOptions{
		GatewayURL:     s.gateway,
		ProviderName:   a.Provider,
		UserID:         userID,
		ProviderScopes: scopes,
		ReturnURL:      s.returnURL,
	})
	if err != nil {
		return textResult(true, "request access failed: "+err.Error())
	}

	sess := s.ensureSession()
	s.sessionMu.Lock()
	sess.AddConnection(principal.Connection{
		Provider:     pending.Provider,
		ConnectionID: pending.ConnectionID,
		GatewayURL:   pending.GatewayURL,
		Scopes:       pending.Scopes,
		Status:       "pending",
		CreatedAt:    time.Now(),
	})
	s.sessionMu.Unlock()
	s.saveSession()

	msg := fmt.Sprintf(
		"Access to %q requested. Ask the human to open this URL and approve consent:\n\n%s\n\n"+
			"Then call connection_status with provider=%q until it reports active.",
		a.Provider, pending.AuthURL, a.Provider,
	)
	return textResult(false, msg)
}

func (s *Server) callConnectionStatus(args json.RawMessage) map[string]any {
	provider := extractProvider(args)
	if provider == "" {
		return textResult(true, "provider is required")
	}
	s.sessionMu.Lock()
	sess := s.session
	s.sessionMu.Unlock()
	if sess == nil {
		return textResult(true, "no connection for provider "+provider+"; call request_access first")
	}
	c, ok := sess.GetConnection(provider)
	if !ok {
		return textResult(true, "no connection for provider "+provider+"; call request_access first")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := principal.CheckStatus(ctx, c.GatewayURL, c.ConnectionID)
	if err != nil {
		return textResult(true, "status check failed: "+err.Error())
	}
	if principal.IsActiveStatus(status) && c.Status != "active" {
		c.Status = "active"
		s.sessionMu.Lock()
		sess.AddConnection(c)
		s.sessionMu.Unlock()
		s.saveSession()
	}
	if principal.IsActiveStatus(status) {
		return textResult(false, fmt.Sprintf("%s is active — access granted.", provider))
	}
	return textResult(false, fmt.Sprintf("%s is not active yet (status: %s). The human must complete consent.", provider, status))
}

func (s *Server) callGetCredential(args json.RawMessage) map[string]any {
	// Authorization already ran in handleToolCall; get_credential is deny-by-default there.
	provider := extractProvider(args)
	if provider == "" {
		return textResult(true, "provider is required")
	}
	s.sessionMu.Lock()
	sess := s.session
	s.sessionMu.Unlock()
	if sess == nil {
		return textResult(true, "no connection for provider "+provider)
	}
	c, ok := sess.GetConnection(provider)
	if !ok {
		return textResult(true, "no connection for provider "+provider+"; call request_access first")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := principal.CheckStatus(ctx, c.GatewayURL, c.ConnectionID)
	if err != nil {
		return textResult(true, "status check failed: "+err.Error())
	}
	if !principal.IsActiveStatus(status) {
		return textResult(true, "connection not active (status: "+status+")")
	}
	tok, err := principal.FetchToken(ctx, c.GatewayURL, c.ConnectionID)
	if err != nil {
		return textResult(true, "fetch token failed: "+err.Error())
	}
	return textResult(false, tok)
}
