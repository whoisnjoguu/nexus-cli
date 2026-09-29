// Package proxy runs the local intercepting reverse proxy that gatekeeps agent tool calls.
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// CredentialResolver fetches a short-lived upstream credential for a broker connection.
type CredentialResolver interface {
	Token(ctx context.Context, gatewayURL, connectionID string) (string, error)
}

// Config assembles the dependencies of a proxy server.
type Config struct {
	Port        int
	Strict      bool
	RequireAuth bool
	Verifier    *jwt.Verifier
	Engine      *policy.Engine     // optional declarative policy; nil falls back to method heuristics
	Audit       *audit.Logger      // optional tamper-evident decision log
	Replay      *jwt.ReplayGuard   // optional single-use token enforcement
	Credentials CredentialResolver // optional broker credential injection
	// OnPersistRule persists an "always allow" rule chosen at the HITL prompt. Optional.
	OnPersistRule func(policy.Rule)
}

type ProxyServer struct {
	cfg       Config
	approveMu sync.Mutex // serialize TTY approvals so concurrent calls don't fight over the terminal
}

// New builds a proxy server from an explicit configuration.
func New(cfg Config) *ProxyServer { return &ProxyServer{cfg: cfg} }

// NewProxyServer is a convenience constructor for the minimal proxy (no policy/audit).
func NewProxyServer(port int, strict, requireAuth bool, verifier *jwt.Verifier) *ProxyServer {
	return New(Config{Port: port, Strict: strict, RequireAuth: requireAuth, Verifier: verifier})
}

func (p *ProxyServer) Start() error {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", p.cfg.Port),
		Handler: http.HandlerFunc(p.handleIntercept),
	}
	return server.ListenAndServe()
}

func (p *ProxyServer) handleIntercept(w http.ResponseWriter, r *http.Request) {
	// Never trust client-supplied identity headers: strip them before anything else so the only
	// source of attribution is a cryptographically verified token.
	stripNexusHeaders(r)

	agentID := "anonymous-agent"
	actAsUser := "unknown-user"
	var scopes []string
	var jti string
	var connID, gateway string

	if p.cfg.RequireAuth {
		claims, err := p.authenticate(r)
		if err != nil {
			unauthorized(w, err)
			return
		}
		agentID = claims.AgentID
		actAsUser = claims.ActAs
		scopes = claims.Scopes
		jti = claims.ID
		connID = claims.ConnID
		gateway = claims.Gateway
		if p.cfg.Replay != nil {
			exp := time.Now().Add(time.Minute)
			if claims.ExpiresAt != nil {
				exp = claims.ExpiresAt.Time
			}
			if err := p.cfg.Replay.Use(jti, exp); err != nil {
				unauthorized(w, err)
				return
			}
		}
	}

	sessionID := jti
	if sessionID == "" {
		sessionID = agentID + "|" + actAsUser
	}

	// HTTPS CONNECT tunnels can't be inspected per-request; decide on the tunnel host itself.
	if r.Method == http.MethodConnect {
		req := policy.Request{SessionID: sessionID, JTI: jti, Method: r.Method, Host: r.Host, Scopes: scopes}
		dec := p.decide(req)
		if !p.enforce(w, dec, req, agentID, actAsUser, r.Host, "") {
			return
		}
		p.handleTunnel(w, r)
		return
	}

	host := r.Host
	if r.URL.IsAbs() {
		host = r.URL.Host
	}
	req := policy.Request{SessionID: sessionID, JTI: jti, Method: r.Method, Host: host, Path: r.URL.Path, Scopes: scopes}
	dec := p.decide(req)
	if !p.enforce(w, dec, req, agentID, actAsUser, host+r.URL.Path, r.URL.RawQuery) {
		return
	}

	// Resolve a broker credential to inject when the matched rule requests it.
	injectToken := ""
	if dec.Rule != nil && dec.Rule.Inject {
		if p.cfg.Credentials == nil || connID == "" {
			p.record(jti, agentID, actAsUser, r.Method, host+r.URL.Path, scopes, false, "credential injection required but no broker connection on token")
			http.Error(w, `{"error": "Forbidden", "message": "credential injection required but unavailable"}`, http.StatusForbidden)
			return
		}
		tok, terr := p.cfg.Credentials.Token(r.Context(), gateway, connID)
		if terr != nil {
			p.record(jti, agentID, actAsUser, r.Method, host+r.URL.Path, scopes, false, "credential fetch failed: "+terr.Error())
			http.Error(w, fmt.Sprintf(`{"error": "BadGateway", "message": %q}`, terr.Error()), http.StatusBadGateway)
			return
		}
		injectToken = tok
	}

	// Absolute request URI means we were reached as a forward proxy (HTTP_PROXY) -> forward it.
	if r.URL.IsAbs() {
		p.forward(w, r, agentID, actAsUser, injectToken)
		return
	}

	// Direct request (no upstream): keep a verification stub so health checks / demos work.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Nexus-Verified", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "allowed", "message": "Tool call verified by Nexus CLI (no upstream; set HTTP_PROXY to forward)"}`))
}

// decide resolves the action for a request: the policy engine when present, else method heuristics.
func (p *ProxyServer) decide(req policy.Request) policy.Decision {
	if p.cfg.Engine != nil {
		return p.cfg.Engine.Evaluate(req)
	}
	// Legacy fallback: writes/deletes (and everything in strict mode) require approval.
	isWrite := req.Method == http.MethodPost || req.Method == http.MethodPut ||
		req.Method == http.MethodPatch || req.Method == http.MethodDelete
	if isWrite || p.cfg.Strict {
		return policy.Decision{Action: policy.ActionHITL, Reason: "high-risk method"}
	}
	return policy.Decision{Action: policy.ActionAllow, Reason: "read-only"}
}

// enforce applies a decision, prompting for HITL when needed and recording the outcome.
// It returns true if the request may proceed.
func (p *ProxyServer) enforce(w http.ResponseWriter, dec policy.Decision, req policy.Request, agentID, actAsUser, target, params string) bool {
	allowed := false
	reason := dec.Reason
	switch dec.Action {
	case policy.ActionAllow:
		allowed = true
	case policy.ActionHITL:
		d := p.approve(agentID, actAsUser, req.Method, target, params, dec.Reason)
		allowed = d.Allowed()
		switch d {
		case hitl.Deny:
			reason = "denied at human-in-the-loop"
		case hitl.Once:
			reason = "approved once"
		case hitl.Session:
			reason = "approved for session"
			if p.cfg.Engine != nil {
				p.cfg.Engine.GrantSession(req)
			}
		case hitl.Always:
			reason = "approved & persisted"
			if p.cfg.Engine != nil {
				p.cfg.Engine.GrantSession(req)
			}
			p.persistAllow(req)
		}
	case policy.ActionDeny:
		allowed = false
	}

	p.record(req.JTI, agentID, actAsUser, req.Method, target, req.Scopes, allowed, reason)
	if !allowed {
		denied(w)
	}
	return allowed
}

// persistAllow writes an "always allow" rule for this request shape via the configured callback.
func (p *ProxyServer) persistAllow(req policy.Request) {
	if p.cfg.OnPersistRule == nil {
		return
	}
	var m policy.Match
	if req.Tool != "" {
		m = policy.Match{Tool: req.Tool, Provider: req.Provider}
	} else {
		m = policy.Match{Method: req.Method, Host: req.Host}
	}
	p.cfg.OnPersistRule(policy.Rule{Match: m, Action: policy.ActionAllow})
}

func (p *ProxyServer) record(jti, agentID, actAsUser, method, target string, scopes []string, allowed bool, reason string) {
	if p.cfg.Audit == nil {
		return
	}
	outcome := "deny"
	if allowed {
		outcome = "allow"
	}
	_ = p.cfg.Audit.Log(audit.Entry{
		JTI:      jti,
		Agent:    agentID,
		ActAs:    actAsUser,
		Tool:     method,
		Target:   target,
		Scopes:   scopes,
		Decision: outcome,
		Reason:   reason,
	})
}

// forward proxies an allowed HTTP request to its real upstream, injecting dual-actor attribution
// headers and, when provided, a broker-issued upstream credential (secretless egress).
func (p *ProxyServer) forward(w http.ResponseWriter, r *http.Request, agentID, actAsUser, injectToken string) {
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.Header.Set("X-Nexus-Agent-ID", agentID)
			req.Header.Set("X-Nexus-Act-As", actAsUser)
			req.Header.Set("X-Nexus-Verified", "true")
			// Never leak the nexus dual-actor token upstream.
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("X-Nexus-Token")
			if injectToken != "" {
				req.Header.Set("Authorization", "Bearer "+injectToken)
			} else {
				req.Header.Del("Authorization")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("X-Nexus-Verified", "true")
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			rw.Header().Set("Content-Type", "application/json")
			http.Error(rw, fmt.Sprintf(`{"error": "BadGateway", "message": %q}`, err.Error()), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// handleTunnel establishes a raw TCP tunnel for CONNECT (HTTPS) requests.
func (p *ProxyServer) handleTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		_ = destConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		_ = destConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go tunnel(destConn, clientConn)
	go tunnel(clientConn, destConn)
}

func tunnel(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

// approve renders the HITL prompt and blocks until the human decides. It fails closed when no
// interactive terminal is attached, and serializes prompts so concurrent calls don't collide.
func (p *ProxyServer) approve(agentID, actAsUser, method, uri, params, reason string) hitl.Decision {
	if !isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "[nexus] no interactive terminal; denying high-risk call %s %s (%s)\n", method, uri, reason)
		return hitl.Deny
	}

	p.approveMu.Lock()
	defer p.approveMu.Unlock()

	respCh := make(chan hitl.Decision)
	req := hitl.ApprovalRequest{
		AgentID:    agentID,
		ActAsUser:  actAsUser,
		ToolName:   method,
		TargetURI:  uri,
		Params:     params,
		Reason:     reason,
		ResponseCh: respCh,
	}

	prog := tea.NewProgram(hitl.NewModel(req))
	go func() {
		if _, err := prog.Run(); err != nil {
			respCh <- hitl.Deny
		}
	}()

	return <-respCh
}

func denied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"error": "Forbidden", "message": "Tool execution denied by Nexus policy"}`, http.StatusForbidden)
}

// authenticate verifies the dual-actor bearer token carried on the request.
func (p *ProxyServer) authenticate(r *http.Request) (*jwt.DualActorClaims, error) {
	if p.cfg.Verifier == nil {
		return nil, fmt.Errorf("auth required but no verifier configured")
	}
	tok := bearerToken(r)
	if tok == "" {
		return nil, fmt.Errorf("missing dual-actor bearer token")
	}
	return p.cfg.Verifier.Verify(tok)
}

func bearerToken(r *http.Request) string {
	for _, h := range []string{"Authorization", "Proxy-Authorization"} {
		v := r.Header.Get(h)
		if len(v) >= 7 && strings.EqualFold(v[:7], "bearer ") {
			return strings.TrimSpace(v[7:])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Nexus-Token"))
}

func stripNexusHeaders(r *http.Request) {
	for h := range r.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-nexus-") {
			r.Header.Del(h)
		}
	}
}

func unauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, fmt.Sprintf(`{"error": "Unauthorized", "message": %q}`, err.Error()), http.StatusUnauthorized)
}
