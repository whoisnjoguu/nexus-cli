// Package mcp serves nexus-cli as a Model Context Protocol server and gateway: it aggregates
// upstream MCP servers (stdio or Streamable HTTP), gates every tool call, resource read, prompt
// and sampling request through the policy engine, human-in-the-loop approval and the audit log,
// and serves the result to agent hosts over stdio or Streamable HTTP.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

// Defaults for Config durations and limits.
const (
	DefaultCallTimeout     = 5 * time.Minute
	DefaultApprovalTimeout = 2 * time.Minute
	DefaultMaxConcurrency  = 32

	// stdioDrainGrace is how long in-flight requests may still answer after stdin closes.
	stdioDrainGrace = 5 * time.Second
)

// Server is the MCP gateway. One Server shares upstreams and the policy engine across every
// connected client session (the stdio host and/or Streamable HTTP sessions).
type Server struct {
	signer   *jwt.TokenSigner
	strict   bool
	engine   *policy.Engine
	auditlog *audit.Logger
	agentID  string
	actAs    string
	ceiling  []string
	version  string
	in       *bufio.Scanner
	out      io.Writer
	logf     func(string, ...any)

	callTimeout     time.Duration
	approvalTimeout time.Duration
	oob             hitl.Approver // out-of-band approver (the control-API broker)
	sem             chan struct{}

	// upstream lifecycle tuning (unexported so tests can shorten it)
	disableRestart     bool
	restartMin         time.Duration
	restartMax         time.Duration
	maxRestartFailures int
	stableAfter        time.Duration

	baseCtx    context.Context
	baseCancel context.CancelFunc
	closeOnce  sync.Once

	sessMu   sync.Mutex
	sessions map[string]*clientSession

	// gateway routing: upstream MCP servers this gateway aggregates and gates.
	upstreams []*upstream
	routeMu   sync.RWMutex
	toolRoute map[string]*upstream
	uriMu     sync.Mutex
	uriOwner  map[string]*upstream
	subMu     sync.Mutex
	subs      map[string]map[*clientSession]bool
	progMu    sync.Mutex
	progSeq   int
	progress  map[string]progressRoute

	status statusWriter

	// broker access: provider connections the agent can request/use via the Gateway.
	gateway        string
	session        *principal.Principal
	sessionPath    string
	sessionMu      sync.Mutex
	returnURL      string
	returnShutdown func()
	persistRule    func(policy.Rule)
}

// Config wires optional policy, audit, identity and gateway behaviour into the server.
type Config struct {
	Signer      *jwt.TokenSigner
	Strict      bool
	Engine      *policy.Engine
	Audit       *audit.Logger
	AgentID     string
	ActAs       string
	Ceiling     []string
	Upstreams   []UpstreamSpec
	Gateway     string               // nexus-framework Gateway URL for broker access tools
	Session     *principal.Principal // logged-in human + existing connections
	SessionPath string               // where to persist new connections
	// OnPersistRule persists an "always allow" rule chosen at an approval prompt. Optional.
	OnPersistRule func(policy.Rule)

	// Version is reported as serverInfo.version to clients and clientInfo.version to upstreams.
	Version string
	// CallTimeout bounds each forwarded upstream request (default 5m). On expiry the upstream is
	// sent notifications/cancelled and the client gets an error.
	CallTimeout time.Duration
	// ApprovalTimeout bounds a human-in-the-loop approval (default 2m); expiry denies.
	ApprovalTimeout time.Duration
	// Approver answers approvals out of band (e.g. a hitl.Broker behind the control API used by
	// `nexus-cli approve`). It races MCP elicitation when the client supports it.
	Approver hitl.Approver
	// DisableRestart leaves crashed upstreams down instead of restarting them with backoff.
	DisableRestart bool
	// MaxConcurrency bounds concurrently handled client requests across all sessions (default 32).
	MaxConcurrency int
	// StatusDir, when set, receives a <pid>.json status file (see ReadStatusFiles).
	StatusDir string
	// PolicyPath and HTTPAddr are informational, recorded in the status file.
	PolicyPath string
	HTTPAddr   string

	// In, Out and Log default to os.Stdin, os.Stdout and os.Stderr.
	In  io.Reader
	Out io.Writer
	Log io.Writer

	tune func(*Server) // test hook: adjust internals before upstreams start
}

// NewServer wires an MCP server to stdin/stdout, logging only to stderr to avoid corrupting the protocol.
func NewServer(signer *jwt.TokenSigner, strict bool) *Server {
	s, _ := New(Config{Signer: signer, Strict: strict})
	return s
}

// New builds a server from an explicit configuration, starting any configured upstream servers.
// Upstreams that fail to start are retried in the background (unless DisableRestart is set); only
// invalid upstream specs are reported as errors.
func New(cfg Config) (*Server, error) {
	for _, spec := range cfg.Upstreams {
		if err := spec.validate(); err != nil {
			return nil, err
		}
	}
	if cfg.In == nil {
		cfg.In = os.Stdin
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.Log == nil {
		cfg.Log = os.Stderr
	}
	s := newServer(cfg.Signer, cfg.Strict, cfg.In, cfg.Log, cfg.Out)
	s.engine = cfg.Engine
	s.auditlog = cfg.Audit
	s.ceiling = cfg.Ceiling
	s.gateway = cfg.Gateway
	s.session = cfg.Session
	s.sessionPath = cfg.SessionPath
	s.persistRule = cfg.OnPersistRule
	s.oob = cfg.Approver
	s.disableRestart = cfg.DisableRestart
	if cfg.AgentID != "" {
		s.agentID = cfg.AgentID
	}
	if cfg.ActAs != "" {
		s.actAs = cfg.ActAs
	}
	if cfg.Version != "" {
		s.version = cfg.Version
	}
	if cfg.CallTimeout > 0 {
		s.callTimeout = cfg.CallTimeout
	}
	if cfg.ApprovalTimeout > 0 {
		s.approvalTimeout = cfg.ApprovalTimeout
	}
	if cfg.MaxConcurrency > 0 {
		s.sem = make(chan struct{}, cfg.MaxConcurrency)
	}
	// One persistent loopback landing page serves every request_access consent redirect.
	if s.gateway != "" {
		if url, sd, lerr := principal.ReturnURLServer(); lerr == nil {
			s.returnURL = url
			s.returnShutdown = sd
		}
	}
	if cfg.tune != nil {
		cfg.tune(s)
	}
	s.status.configure(s, cfg.StatusDir, cfg.PolicyPath, cfg.HTTPAddr)
	s.startUpstreams(cfg.Upstreams)
	s.status.start()
	return s, nil
}

func newServer(signer *jwt.TokenSigner, strict bool, in io.Reader, logw, out io.Writer) *Server {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		signer:             signer,
		strict:             strict,
		in:                 sc,
		out:                out,
		logf:               func(f string, a ...any) { fmt.Fprintf(logw, "[nexus-mcp] "+f+"\n", a...) },
		version:            "dev",
		agentID:            "mcp-agent",
		actAs:              "unknown-user",
		callTimeout:        DefaultCallTimeout,
		approvalTimeout:    DefaultApprovalTimeout,
		sem:                make(chan struct{}, DefaultMaxConcurrency),
		restartMin:         time.Second,
		restartMax:         30 * time.Second,
		maxRestartFailures: 5,
		stableAfter:        30 * time.Second,
		baseCtx:            ctx,
		baseCancel:         cancel,
		sessions:           make(map[string]*clientSession),
		toolRoute:          make(map[string]*upstream),
		uriOwner:           make(map[string]*upstream),
		subs:               make(map[string]map[*clientSession]bool),
		progress:           make(map[string]progressRoute),
	}
}

// Serve speaks newline-delimited JSON-RPC over the configured stdin/stdout (MCP stdio transport)
// until stdin closes. Each request runs in its own goroutine (bounded by MaxConcurrency) so a slow
// upstream call or a pending approval never blocks other requests; initialize is handled inline.
func (s *Server) Serve() error {
	s.logf("serving MCP over stdio (strict=%v)", s.strict)
	sess := s.newSession("stdio", &writerSink{w: s.out})

	var wg sync.WaitGroup
	for s.in.Scan() {
		line := strings.TrimSpace(s.in.Text())
		if line == "" {
			continue
		}
		var msg rpcMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			s.logf("parse error: %v", err)
			_ = sess.def.send(outgoing{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: newErr(-32700, "parse error")})
			continue
		}
		if !msg.isRequest() || msg.Method == "initialize" {
			s.process(sess, msg, sess.def)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case s.sem <- struct{}{}:
			case <-sess.ctx.Done():
				return
			}
			defer func() { <-s.sem }()
			s.process(sess, msg, sess.def)
		}()
	}
	// stdin closed: give in-flight requests a short grace period to answer, then cancel the rest.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stdioDrainGrace):
	}
	sess.close()
	<-done
	return s.in.Err()
}

// reqCtx carries one client request through the handlers.
type reqCtx struct {
	ctx    context.Context
	sess   *clientSession
	out    sink // where messages related to this request (and its response) go
	id     json.RawMessage
	method string
	params json.RawMessage
}

func (rc *reqCtx) rel() *relation { return &relation{sess: rc.sess, out: rc.out} }

// process handles one inbound message synchronously, writing any response to out.
func (s *Server) process(sess *clientSession, msg rpcMessage, out sink) {
	sess.touch()
	switch {
	case msg.isResponse():
		sess.deliver(msg)
		return
	case msg.isNotification():
		s.handleNotification(sess, msg)
		return
	case !msg.isRequest():
		return
	}
	ctx, end := sess.begin(msg.ID)
	rc := &reqCtx{ctx: ctx, sess: sess, out: out, id: msg.ID, method: msg.Method, params: msg.Params}
	result, rerr := s.safeHandle(rc)
	if end() {
		return // cancelled by the client: MCP says no response is sent
	}
	var err error
	if rerr != nil {
		err = out.send(outgoing{JSONRPC: "2.0", ID: msg.ID, Error: rerr})
	} else {
		if result == nil {
			result = map[string]any{}
		}
		err = out.send(outgoing{JSONRPC: "2.0", ID: msg.ID, Result: result})
	}
	if err != nil {
		s.logf("write response for %s: %v", msg.Method, err)
	}
}

func (s *Server) safeHandle(rc *reqCtx) (result any, rerr *rpcError) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("panic handling %s: %v", rc.method, r)
			result, rerr = nil, newErr(codeInternal, "internal error")
		}
	}()
	return s.handleRequest(rc)
}

func (s *Server) handleNotification(sess *clientSession, msg rpcMessage) {
	switch msg.Method {
	case "notifications/initialized":
		sess.mu.Lock()
		sess.initialized = true
		sess.mu.Unlock()
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(msg.Params, &p) == nil && hasID(p.RequestID) {
			sess.cancelRequest(p.RequestID)
		}
	case "notifications/roots/list_changed":
		for _, u := range s.upstreams {
			go u.notify("notifications/roots/list_changed", map[string]any{})
		}
	}
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
	Capabilities    struct {
		Elicitation *json.RawMessage `json:"elicitation"`
		Sampling    *json.RawMessage `json:"sampling"`
		Roots       *json.RawMessage `json:"roots"`
	} `json:"capabilities"`
}

func (s *Server) handleInitialize(rc *reqCtx) (any, *rpcError) {
	var ip initializeParams
	_ = json.Unmarshal(rc.params, &ip)
	version := negotiateVersion(ip.ProtocolVersion)
	sess := rc.sess
	sess.mu.Lock()
	sess.caps = clientCaps{
		elicitation: ip.Capabilities.Elicitation != nil,
		sampling:    ip.Capabilities.Sampling != nil,
		roots:       ip.Capabilities.Roots != nil,
	}
	sess.protocol = version
	// Treat the session as live right away: some clients never send notifications/initialized.
	sess.initialized = true
	caps := sess.caps
	sess.mu.Unlock()
	s.logf("initialized: protocol=%s (requested %q) elicitation=%v sampling=%v roots=%v strict=%v",
		version, ip.ProtocolVersion, caps.elicitation, caps.sampling, caps.roots, s.strict)
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    s.advertisedCapabilities(),
		"serverInfo":      map[string]any{"name": serverName, "version": s.version},
	}, nil
}

func (s *Server) handleRequest(rc *reqCtx) (any, *rpcError) {
	switch rc.method {
	case "initialize":
		return s.handleInitialize(rc)
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.allTools()}, nil
	case "tools/call":
		return s.handleToolCall(rc)
	case "resources/list":
		return s.listPaged(rc, "resources/list", "resources", "resources", func(u *upstream, item map[string]any) {
			if uri, ok := item["uri"].(string); ok {
				s.setURIOwner(uri, u)
			}
		})
	case "resources/templates/list":
		return s.listPaged(rc, "resources/templates/list", "resourceTemplates", "resources", nil)
	case "resources/read":
		return s.handleResourceRead(rc)
	case "resources/subscribe", "resources/unsubscribe":
		return s.handleSubscribe(rc)
	case "prompts/list":
		return s.listPaged(rc, "prompts/list", "prompts", "prompts", func(u *upstream, item map[string]any) {
			if name, ok := item["name"].(string); ok {
				item["name"] = u.prefix + name
			}
		})
	case "prompts/get":
		return s.handlePromptGet(rc)
	case "completion/complete":
		return s.handleComplete(rc)
	case "logging/setLevel":
		return s.handleSetLevel(rc)
	}
	return nil, newErr(codeMethodNotFound, "method not found: "+rc.method)
}

// Close stops every upstream, every client session, the status file and the consent server.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.baseCancel()
		s.sessMu.Lock()
		var all []*clientSession
		for _, ss := range s.sessions {
			all = append(all, ss)
		}
		s.sessMu.Unlock()
		for _, ss := range all {
			ss.close()
		}
		var wg sync.WaitGroup
		for _, up := range s.upstreams {
			wg.Add(1)
			go func(u *upstream) {
				defer wg.Done()
				u.shutdown()
			}(up)
		}
		wg.Wait()
		s.status.stop()
		if s.returnShutdown != nil {
			s.returnShutdown()
		}
	})
}
