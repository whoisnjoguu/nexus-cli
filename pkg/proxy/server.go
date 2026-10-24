// Package proxy runs the local intercepting reverse proxy that gatekeeps agent tool calls.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
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
	Listen string
	// Strict requires a human decision for every call: with a policy engine, calls it would allow
	// are escalated to HITL (session approvals still stick); without one, every call asks.
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
	// Approver collects HITL decisions. Nil fails closed: every HITL decision is denied with a
	// hint on stderr.
	Approver hitl.Approver
	// ApprovalTimeout bounds how long a request waits for a human (default 60s); expiry denies.
	ApprovalTimeout time.Duration
	// OnPersistRule persists an "always allow" rule chosen at the HITL prompt. Optional.
	OnPersistRule func(policy.Rule)
	// MITM, when set, terminates CONNECT tunnels with leaf certificates from this CA so every
	// HTTPS request inside gets the full per-request pipeline. Nil keeps host-level tunnels.
	MITM *ca.CA
	// Passthrough lists host patterns (policy egress glob semantics) never intercepted: they get
	// the host-level CONNECT decision and a raw tunnel even when MITM is set.
	Passthrough []string
	// UpstreamTransport forwards allowed requests. Nil uses a clone of http.DefaultTransport
	// (TLS verification always on).
	UpstreamTransport http.RoundTripper
}

// ListenAddr returns the address the proxy binds: Listen, or 127.0.0.1:<Port> when empty.
func (c Config) ListenAddr() string {
	if c.Listen != "" {
		return c.Listen
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port))
}

type ProxyServer struct {
	cfg       Config
	transport http.RoundTripper
	stderr    io.Writer

	hintMu   sync.Mutex
	hintLast map[string]time.Time // host -> last "client rejected nexus CA" hint

	mu      sync.Mutex
	runCtx  context.Context // cancelled when Serve begins shutting down; aborts pending approvals
	tunnels map[net.Conn]struct{}
	closing bool
	tunWG   sync.WaitGroup
	self    string // bound listen address, used to avoid proxying upstream traffic to ourselves
}

// New builds a proxy server from an explicit configuration.
func New(cfg Config) *ProxyServer {
	if cfg.Replay == nil {
		cfg.Replay = jwt.NewReplayGuard()
	}
	if cfg.ApprovalTimeout <= 0 {
		cfg.ApprovalTimeout = DefaultApprovalTimeout
	}
	p := &ProxyServer{
		cfg:      cfg,
		stderr:   os.Stderr,
		hintLast: make(map[string]time.Time),
		runCtx:   context.Background(),
		tunnels:  make(map[net.Conn]struct{}),
	}
	p.transport = cfg.UpstreamTransport
	if p.transport == nil {
		p.transport = p.defaultTransport()
	}
	return p
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
	p.self = ln.Addr().String()
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
	// Capture the presented token before the x-nexus-* sweep below removes X-Nexus-Token.
	tok, src := extractToken(r)

	if !r.URL.IsAbs() && r.Method == http.MethodGet && r.URL.Path == HealthPath {
		p.serveHealth(w, tok)
		return
	}

	// Never trust client-supplied identity headers: strip them before anything else so the only
	// source of attribution is a cryptographically verified token.
	stripNexusHeaders(r)

	id, err := p.identify(tok, src)
	if err != nil {
		if r.Method == http.MethodConnect {
			proxyAuthRequired(w, err)
		} else {
			unauthorized(w, err)
		}
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, id)
		return
	}

	host := r.Host
	if r.URL.IsAbs() {
		host = r.URL.Host
	}
	p.pipeline(w, r, id, host, r.URL.IsAbs())
}

// serveHealth answers the liveness probe. When a token is presented it also reports whether the
// token verifies (without consuming it), so `nexus-cli run --attach` can detect a key mismatch.
func (p *ProxyServer) serveHealth(w http.ResponseWriter, tok string) {
	h := map[string]string{"status": "ok", "service": "nexus-cli", "mitm": "off"}
	if p.cfg.MITM != nil {
		h["mitm"] = "on"
		h["ca_fingerprint"] = p.cfg.MITM.Fingerprint()
	}
	if tok != "" && p.cfg.RequireAuth {
		if _, err := p.authenticate(tok); err != nil {
			h["token"] = "invalid"
		} else {
			h["token"] = "valid"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h)
}

// identity is the verified caller of a request (or of every request inside a CONNECT tunnel).
type identity struct {
	agentID string
	actAs   string
	scopes  []string
	jti     string
	connID  string
	gateway string
	authSrc tokenSource
}

// sessionID keys session state (taint, grants, one-time rules) on the agent+human pair rather
// than any single jti, since tokens may be reused or rotated.
func (id identity) sessionID() string { return id.agentID + "|" + id.actAs }

// identify authenticates the presented token (when auth is required) and enforces single use.
func (p *ProxyServer) identify(tok string, src tokenSource) (identity, error) {
	id := identity{agentID: "anonymous-agent", actAs: "unknown-user", authSrc: tokenNone}
	if !p.cfg.RequireAuth {
		return id, nil
	}
	claims, err := p.authenticate(tok)
	if err != nil {
		return id, err
	}
	id = identity{
		agentID: claims.AgentID,
		actAs:   claims.ActAs,
		scopes:  claims.Scopes,
		jti:     claims.ID,
		connID:  claims.ConnID,
		gateway: claims.Gateway,
		authSrc: src,
	}
	if p.cfg.SingleUse || claims.SingleUse {
		exp := time.Now().Add(time.Minute)
		if claims.ExpiresAt != nil {
			exp = claims.ExpiresAt.Time
		}
		if err := p.cfg.Replay.Use(id.jti, exp); err != nil {
			return id, err
		}
	}
	return id, nil
}

// pipeline runs the per-request gate shared by plain HTTP and intercepted HTTPS requests:
// decide -> enforce/HITL -> credential injection -> audit -> forward. forward=false serves the
// local verification stub instead (a direct, non-proxied request).
func (p *ProxyServer) pipeline(w http.ResponseWriter, r *http.Request, id identity, host string, forward bool) {
	target := host + r.URL.Path
	req := policy.Request{SessionID: id.sessionID(), JTI: id.jti, Method: r.Method, Host: host, Path: r.URL.Path, Scopes: id.scopes}
	dec := p.decide(req)
	if !p.enforce(r.Context(), w, dec, req, id.agentID, id.actAs, target, r.URL.RawQuery) {
		return
	}

	// Resolve a broker credential to inject when the matched rule requests it.
	injectToken := ""
	if dec.Rule != nil && dec.Rule.Inject {
		if p.cfg.Credentials == nil || id.connID == "" {
			p.record(id.jti, id.agentID, id.actAs, r.Method, target, id.scopes, false, "credential injection required but no broker connection on token")
			http.Error(w, `{"error": "Forbidden", "message": "credential injection required but unavailable"}`, http.StatusForbidden)
			return
		}
		tok, terr := p.cfg.Credentials.Token(r.Context(), id.gateway, id.connID)
		if terr != nil {
			p.record(id.jti, id.agentID, id.actAs, r.Method, target, id.scopes, false, "credential fetch failed: "+terr.Error())
			http.Error(w, fmt.Sprintf(`{"error": "BadGateway", "message": %q}`, terr.Error()), http.StatusBadGateway)
			return
		}
		injectToken = tok
	}

	if forward {
		p.forward(w, r, id.agentID, id.actAs, injectToken, id.authSrc == tokenAuthorization)
		return
	}

	// Direct request (no upstream): keep a verification stub so health checks / demos work.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Nexus-Verified", "true")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "allowed", "message": "Tool call verified by Nexus CLI (no upstream; set HTTP_PROXY to forward)"}`))
}

// handleConnect gates a CONNECT: intercepted (per-request policy) when a MITM CA is configured
// and the host isn't passthrough, otherwise a host-level decision plus a raw tunnel.
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request, id identity) {
	if p.cfg.MITM != nil && !policy.HostMatches(p.cfg.Passthrough, r.Host) {
		p.handleMITM(w, r, id)
		return
	}
	req := policy.Request{SessionID: id.sessionID(), JTI: id.jti, Method: r.Method, Host: r.Host, Scopes: id.scopes}
	dec := p.decide(req)
	if !p.enforce(r.Context(), w, dec, req, id.agentID, id.actAs, r.Host, "") {
		return
	}
	p.handleTunnel(w, r)
}

// decide resolves the action for a request: the policy engine when present, else method heuristics.
func (p *ProxyServer) decide(req policy.Request) policy.Decision {
	if p.cfg.Engine != nil {
		dec := p.cfg.Engine.Evaluate(req)
		// Strict mode puts a human in front of every call the policy would silently allow, unless
		// they already approved this shape of call for the session.
		if p.cfg.Strict && dec.Action == policy.ActionAllow && !p.cfg.Engine.SessionGranted(req) {
			return policy.Decision{Action: policy.ActionHITL, Rule: dec.Rule, Reason: "strict mode: " + dec.Reason}
		}
		return dec
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
		fmt.Fprintf(p.stderr, "[nexus] denying %s %s (%s): no approver attached — start the proxy with 'nexus-cli dev' and answer with 'nexus-cli approve'\n", req.Tool, req.Target, req.Reason)
		d = hitl.Deny
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
		Transport: p.transport,
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

// proxyAuthRequired rejects an unauthenticated CONNECT with a proxy challenge, before any TLS.
func proxyAuthRequired(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Proxy-Authenticate", `Basic realm="nexus"`)
	http.Error(w, fmt.Sprintf(`{"error": "ProxyAuthenticationRequired", "message": %q}`, err.Error()), http.StatusProxyAuthRequired)
}

// defaultTransport clones http.DefaultTransport (keeping its dial/TLS/idle timeouts and full TLS
// verification), pins HTTP/1.1 so Upgrade (websocket) requests work through ReverseProxy, and
// honours an environment proxy unless it points back at this proxy.
func (p *ProxyServer) defaultTransport() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	t.Proxy = func(r *http.Request) (*url.URL, error) {
		u, err := http.ProxyFromEnvironment(r)
		if err != nil || u == nil {
			return u, err
		}
		p.mu.Lock()
		self := p.self
		p.mu.Unlock()
		if self != "" && sameHostPort(u.Host, self) {
			return nil, nil
		}
		return u, nil
	}
	return t
}

func sameHostPort(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || ap != bp {
		return false
	}
	if strings.EqualFold(ah, bh) {
		return true
	}
	isLocal := func(h string) bool {
		if strings.EqualFold(h, "localhost") {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
	}
	return isLocal(ah) && isLocal(bh)
}
