// Package proxy runs the local intercepting reverse proxy that gatekeeps agent tool calls.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
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

// Default timeouts applied by Serve and enforce.
const (
	DefaultApprovalTimeout = 60 * time.Second
	shutdownGrace          = 5 * time.Second
	readHeaderTimeout      = 10 * time.Second
	idleTimeout            = 2 * time.Minute
)

// HealthPath is answered directly (no auth, policy or audit) for liveness probes.
const HealthPath = "/_nexus/health"

// Config assembles the dependencies of a proxy server.
type Config struct {
	Port int
	// Listen is the host:port to bind. Empty derives 127.0.0.1:<Port> so the proxy is never
	// exposed beyond the local machine by accident.
	Listen      string
	Strict      bool
	RequireAuth bool
	Verifier    *jwt.Verifier
	Engine      *policy.Engine     // optional declarative policy; nil falls back to method heuristics
	Audit       *audit.Logger      // optional tamper-evident decision log
	Replay      *jwt.ReplayGuard   // jti store for single-use tokens; one is created when nil
	Credentials CredentialResolver // optional broker credential injection
	// SingleUse rejects every reuse of a token's jti. When false, tokens are reusable until expiry
	// unless they carry the single_use claim.
	SingleUse bool
	// Approver collects HITL decisions. Nil falls back to an interactive terminal prompt that
	// fails closed when no TTY is attached.
	Approver hitl.Approver
	// ApprovalTimeout bounds how long a request waits for a human (default 60s); expiry denies.
	ApprovalTimeout time.Duration
	// OnPersistRule persists an "always allow" rule chosen at the HITL prompt. Optional.
	OnPersistRule func(policy.Rule)
}

// ListenAddr returns the address the proxy binds: Listen, or 127.0.0.1:<Port> when empty.
func (c Config) ListenAddr() string {
	if c.Listen != "" {
		return c.Listen
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port))
}

type ProxyServer struct {
	cfg     Config
	ttySema chan struct{} // serialize TTY approvals so concurrent calls don't fight over the terminal

	mu      sync.Mutex
	runCtx  context.Context // cancelled when Serve begins shutting down; aborts pending approvals
	tunnels map[net.Conn]struct{}
	closing bool
	tunWG   sync.WaitGroup
}

// New builds a proxy server from an explicit configuration.
func New(cfg Config) *ProxyServer {
	if cfg.Replay == nil {
		cfg.Replay = jwt.NewReplayGuard()
	}
	if cfg.ApprovalTimeout <= 0 {
		cfg.ApprovalTimeout = DefaultApprovalTimeout
	}
	return &ProxyServer{
		cfg:     cfg,
		ttySema: make(chan struct{}, 1),
		runCtx:  context.Background(),
		tunnels: make(map[net.Conn]struct{}),
	}
}

// NewProxyServer is a convenience constructor for the minimal proxy (no policy/audit).
func NewProxyServer(port int, strict, requireAuth bool, verifier *jwt.Verifier) *ProxyServer {
	return New(Config{Port: port, Strict: strict, RequireAuth: requireAuth, Verifier: verifier})
}

// Start serves on Config.ListenAddr until the process exits. Prefer ListenAndServe for shutdown.
func (p *ProxyServer) Start() error { return p.ListenAndServe(context.Background()) }

// ListenAndServe binds Config.ListenAddr and serves until ctx is cancelled. Callers that need the
// bound address (e.g. port 0) should create their own listener and call Serve.
func (p *ProxyServer) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.ListenAddr())
	if err != nil {
		return err
	}
	return p.Serve(ctx, ln)
}

// Serve accepts proxy connections on ln until ctx is cancelled, then shuts down gracefully:
// pending approvals are denied, open CONNECT tunnels are closed and in-flight requests get a
// short grace period. It returns nil on a clean shutdown. Serve takes ownership of ln.
func (p *ProxyServer) Serve(ctx context.Context, ln net.Listener) error {
	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()
	p.mu.Lock()
	p.runCtx = runCtx
	p.closing = false
	p.mu.Unlock()

	srv := &http.Server{
		Handler:           http.HandlerFunc(p.handleIntercept),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		stopRun()
		p.closeTunnels()
		return err
	case <-ctx.Done():
	}

	stopRun()
	p.closeTunnels()
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	shErr := srv.Shutdown(shCtx)
	if shErr != nil {
		_ = srv.Close()
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return shErr
}

// trackTunnel registers hijacked tunnel conns; it returns false once shutdown has begun.
func (p *ProxyServer) trackTunnel(conns ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	for _, c := range conns {
		p.tunnels[c] = struct{}{}
	}
	p.tunWG.Add(1)
	return true
}

func (p *ProxyServer) untrackTunnel(conns ...net.Conn) {
	p.mu.Lock()
	for _, c := range conns {
		delete(p.tunnels, c)
	}
	p.mu.Unlock()
	p.tunWG.Done()
}

// closeTunnels closes every active CONNECT tunnel and waits for their copy loops to exit.
func (p *ProxyServer) closeTunnels() {
	p.mu.Lock()
	p.closing = true
	for c := range p.tunnels {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.tunWG.Wait()
}

func (p *ProxyServer) lifetime() context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.runCtx
}

func (p *ProxyServer) handleIntercept(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() && r.Method == http.MethodGet && r.URL.Path == HealthPath {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"nexus-cli"}`))
		return
	}

	// Capture the presented token before the x-nexus-* sweep below removes X-Nexus-Token.
	tok, src := extractToken(r)

	// Never trust client-supplied identity headers: strip them before anything else so the only
	// source of attribution is a cryptographically verified token.
	stripNexusHeaders(r)

	agentID := "anonymous-agent"
	actAsUser := "unknown-user"
	var scopes []string
	var jti string
	var connID, gateway string
	authSrc := tokenNone

	if p.cfg.RequireAuth {
		claims, err := p.authenticate(tok)
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
		authSrc = src
		if p.cfg.SingleUse || claims.SingleUse {
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

	// Tokens may be reused or rotated, so session state (taint, grants, one-time rules) is keyed on
	// the agent+human pair rather than any single jti.
	sessionID := agentID + "|" + actAsUser

	// HTTPS CONNECT tunnels can't be inspected per-request; decide on the tunnel host itself.
	if r.Method == http.MethodConnect {
		req := policy.Request{SessionID: sessionID, JTI: jti, Method: r.Method, Host: r.Host, Scopes: scopes}
		dec := p.decide(req)
		if !p.enforce(r.Context(), w, dec, req, agentID, actAsUser, r.Host, "") {
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
	if !p.enforce(r.Context(), w, dec, req, agentID, actAsUser, host+r.URL.Path, r.URL.RawQuery) {
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
		p.forward(w, r, agentID, actAsUser, injectToken, authSrc == tokenAuthorization)
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

// enforce applies a decision, asking the Approver for HITL when needed and recording the outcome.
// ctx is the HTTP request context, so a client disconnect cancels a pending approval.
// It returns true if the request may proceed.
func (p *ProxyServer) enforce(ctx context.Context, w http.ResponseWriter, dec policy.Decision, req policy.Request, agentID, actAsUser, target, params string) bool {
	allowed := false
	reason := dec.Reason
	switch dec.Action {
	case policy.ActionAllow:
		allowed = true
	case policy.ActionHITL:
		d, why := p.approve(ctx, hitl.Request{
			ID:        newRequestID(),
			AgentID:   agentID,
			ActAsUser: actAsUser,
			Tool:      req.Method,
			Target:    target,
			Params:    params,
			Reason:    dec.Reason,
			Created:   time.Now(),
		})
		allowed = d.Allowed()
		switch d {
		case hitl.Deny:
			reason = "denied at human-in-the-loop"
			if why != "" {
				reason += " (" + why + ")"
			}
		case hitl.Once:
			reason = "approved once"
		case hitl.Session:
			reason = "approved for session"
			if p.cfg.Engine != nil {
				p.cfg.Engine.GrantSession(req, dec)
			}
		case hitl.Always:
			reason = "approved & persisted"
			if p.cfg.Engine != nil {
				p.cfg.Engine.GrantSession(req, dec)
			}
			p.persistAllow(req, dec.Rule)
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

// approve asks the configured Approver (or the TTY fallback) for a decision, bounded by
// ApprovalTimeout, the request context and server shutdown. Any cancellation fails closed;
// the second result explains a forced denial.
func (p *ProxyServer) approve(parent context.Context, req hitl.Request) (hitl.Decision, string) {
	ctx, cancel := context.WithTimeout(parent, p.cfg.ApprovalTimeout)
	defer cancel()
	stop := context.AfterFunc(p.lifetime(), cancel)
	defer stop()

	var d hitl.Decision
	if p.cfg.Approver != nil {
		d = p.cfg.Approver.Approve(ctx, req)
	} else {
		d = p.approveTTY(ctx, req)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return hitl.Deny, "approval timed out"
		}
		return hitl.Deny, "approval cancelled"
	}
	return d, ""
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// persistAllow writes an "always allow" rule for exactly the request the human saw, keeping the
// matched rule's scope, taints and one-time constraints so persisting never weakens them.
func (p *ProxyServer) persistAllow(req policy.Request, matched *policy.Rule) {
	if p.cfg.OnPersistRule == nil {
		return
	}
	var m policy.Match
	if req.Tool != "" {
		m = policy.Match{Tool: req.Tool, Provider: req.Provider}
	} else {
		m = policy.Match{Method: req.Method, Host: req.Host, Path: req.Path}
	}
	p.cfg.OnPersistRule(policy.PersistedAllow(m, matched))
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
// stripAuthorization removes the client's Authorization header because it carried the nexus token.
func (p *ProxyServer) forward(w http.ResponseWriter, r *http.Request, agentID, actAsUser, injectToken string, stripAuthorization bool) {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			req := pr.Out
			// Never leak proxy credentials or the nexus dual-actor token upstream.
			for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Proxy-Authenticate", "X-Nexus-Token"} {
				req.Header.Del(h)
			}
			switch {
			case injectToken != "":
				req.Header.Set("Authorization", "Bearer "+injectToken)
			case stripAuthorization:
				req.Header.Del("Authorization")
			}
			req.Header.Set("X-Nexus-Agent-ID", agentID)
			req.Header.Set("X-Nexus-Act-As", actAsUser)
			req.Header.Set("X-Nexus-Verified", "true")
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
	var dialer net.Dialer
	dctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	destConn, err := dialer.DialContext(dctx, "tcp", r.Host)
	cancel()
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
	// Hijacked conns are invisible to http.Server, so track them for shutdown.
	if !p.trackTunnel(clientConn, destConn) {
		_ = clientConn.Close()
		_ = destConn.Close()
		return
	}
	// Clear deadlines inherited from the server's header/idle timeouts.
	_ = clientConn.SetDeadline(time.Time{})

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = destConn.Close()
		p.untrackTunnel(clientConn, destConn)
		return
	}

	go func() {
		defer p.untrackTunnel(clientConn, destConn)
		done := make(chan struct{}, 2)
		go func() { tunnel(destConn, clientConn); done <- struct{}{} }()
		go func() { tunnel(clientConn, destConn); done <- struct{}{} }()
		<-done
		<-done
	}()
}

func tunnel(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

// approveTTY renders the interactive HITL prompt and blocks until the human decides or ctx ends.
// It fails closed when no interactive terminal is attached, and serializes prompts so concurrent
// calls don't collide.
func (p *ProxyServer) approveTTY(ctx context.Context, req hitl.Request) hitl.Decision {
	if !isatty.IsTerminal(os.Stdin.Fd()) && !isatty.IsCygwinTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr, "[nexus] no interactive terminal; denying high-risk call %s %s (%s)\n", req.Tool, req.Target, req.Reason)
		return hitl.Deny
	}

	select {
	case p.ttySema <- struct{}{}:
		defer func() { <-p.ttySema }()
	case <-ctx.Done():
		return hitl.Deny
	}

	respCh := make(chan hitl.Decision, 2)
	prog := tea.NewProgram(hitl.NewModel(hitl.ApprovalRequest{
		AgentID:    req.AgentID,
		ActAsUser:  req.ActAsUser,
		ToolName:   req.Tool,
		TargetURI:  req.Target,
		Params:     req.Params,
		Reason:     req.Reason,
		ResponseCh: respCh,
	}))
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		if _, err := prog.Run(); err != nil {
			respCh <- hitl.Deny
		}
	}()

	select {
	case d := <-respCh:
		<-runDone
		return d
	case <-runDone:
		select {
		case d := <-respCh:
			return d
		default:
			return hitl.Deny
		}
	case <-ctx.Done():
		prog.Quit()
		<-runDone
		return hitl.Deny
	}
}

func denied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"error": "Forbidden", "message": "Tool execution denied by Nexus policy"}`, http.StatusForbidden)
}

// authenticate verifies the presented dual-actor token.
func (p *ProxyServer) authenticate(tok string) (*jwt.DualActorClaims, error) {
	if p.cfg.Verifier == nil {
		return nil, fmt.Errorf("auth required but no verifier configured")
	}
	if tok == "" {
		return nil, fmt.Errorf("missing dual-actor token")
	}
	return p.cfg.Verifier.Verify(tok)
}

// tokenSource records which header carried the nexus token, so forwarding strips only that one.
type tokenSource int

const (
	tokenNone tokenSource = iota
	tokenProxyAuthorization
	tokenAuthorization
	tokenXNexus
)

// extractToken finds the nexus token in, by priority: Proxy-Authorization (Bearer, or Basic with
// the token as password, as sent by clients using http://user:token@host:port proxy URLs),
// Authorization: Bearer, then X-Nexus-Token. Authorization: Basic is never a nexus token.
func extractToken(r *http.Request) (string, tokenSource) {
	if v := r.Header.Get("Proxy-Authorization"); v != "" {
		if t := schemeValue(v, "bearer"); t != "" {
			return t, tokenProxyAuthorization
		}
		if enc := schemeValue(v, "basic"); enc != "" {
			if raw, err := base64.StdEncoding.DecodeString(enc); err == nil {
				if _, pass, ok := strings.Cut(string(raw), ":"); ok && strings.TrimSpace(pass) != "" {
					return strings.TrimSpace(pass), tokenProxyAuthorization
				}
			}
		}
	}
	if t := schemeValue(r.Header.Get("Authorization"), "bearer"); t != "" {
		return t, tokenAuthorization
	}
	if t := strings.TrimSpace(r.Header.Get("X-Nexus-Token")); t != "" {
		return t, tokenXNexus
	}
	return "", tokenNone
}

func bearerToken(r *http.Request) string {
	t, _ := extractToken(r)
	return t
}

// schemeValue returns the credentials of an auth header when it uses scheme (case-insensitive).
func schemeValue(v, scheme string) string {
	v = strings.TrimSpace(v)
	if len(v) <= len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) || v[len(scheme)] != ' ' {
		return ""
	}
	return strings.TrimSpace(v[len(scheme)+1:])
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
