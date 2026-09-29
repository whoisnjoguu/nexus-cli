// Package mcp serves nexus-cli as a Model Context Protocol stdio server for agent hosts.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

const (
	protocolVersion = "2026-10-01"
	serverName      = "nexus-security-guardrail"
	serverVersion   = "0.1.0"
)

// Server speaks newline-delimited JSON-RPC 2.0 over stdio (MCP stdio transport).
type Server struct {
	signer   *jwt.TokenSigner
	strict   bool
	engine   *policy.Engine
	auditlog *audit.Logger
	agentID  string
	actAs    string
	ceiling  []string
	in       *bufio.Scanner
	out      io.Writer
	logf     func(string, ...any)

	writeMu sync.Mutex

	idMu  sync.Mutex
	idSeq int

	pendingMu sync.Mutex
	pending   map[string]chan rpcMessage

	clientElicits bool

	// gateway routing: upstream MCP servers this gateway aggregates and gates.
	upstreams []*upstream
	toolRoute map[string]*upstream

	// broker access: provider connections the agent can request/use via the Gateway.
	gateway        string
	session        *principal.Principal
	sessionPath    string
	sessionMu      sync.Mutex
	returnURL      string
	returnShutdown func()
	persistRule    func(policy.Rule)
}

// Config wires optional policy, audit, and identity context into the server.
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
	// OnPersistRule persists an "always allow" rule chosen at an elicitation prompt. Optional.
	OnPersistRule func(policy.Rule)
}

// NewServer wires an MCP server to stdin/stdout, logging only to stderr to avoid corrupting the protocol.
func NewServer(signer *jwt.TokenSigner, strict bool) *Server {
	s, _ := New(Config{Signer: signer, Strict: strict})
	return s
}

// New builds a server from an explicit configuration, spawning any configured upstream servers.
func New(cfg Config) (*Server, error) {
	s := newServer(cfg.Signer, cfg.Strict, os.Stdin, os.Stderr, os.Stdout)
	s.engine = cfg.Engine
	s.auditlog = cfg.Audit
	s.agentID = cfg.AgentID
	s.actAs = cfg.ActAs
	s.ceiling = cfg.Ceiling
	s.gateway = cfg.Gateway
	s.session = cfg.Session
	s.sessionPath = cfg.SessionPath
	s.persistRule = cfg.OnPersistRule
	if s.agentID == "" {
		s.agentID = "mcp-agent"
	}
	if s.actAs == "" {
		s.actAs = "unknown-user"
	}
	// One persistent loopback landing page serves every request_access consent redirect.
	if s.gateway != "" {
		if url, sd, lerr := principal.ReturnURLServer(); lerr == nil {
			s.returnURL = url
			s.returnShutdown = sd
		}
	}
	if len(cfg.Upstreams) > 0 {
		if err := s.startUpstreams(cfg.Upstreams); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func newServer(signer *jwt.TokenSigner, strict bool, in io.Reader, logw, out io.Writer) *Server {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return &Server{
		signer:  signer,
		strict:  strict,
		in:      sc,
		out:     out,
		logf:    func(f string, a ...any) { fmt.Fprintf(logw, "[nexus-mcp] "+f+"\n", a...) },
		pending: make(map[string]chan rpcMessage),
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcMessage is a superset that captures both incoming requests/notifications and responses.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// outgoing is a unified frame for replies and server-initiated requests.
type outgoing struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads stdin on the main goroutine, dispatching requests to a single worker
func (s *Server) Serve() error {
	s.logf("serving MCP over stdio (strict=%v)", s.strict)

	requests := make(chan rpcRequest, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for req := range requests {
			s.handle(req)
		}
	}()

	for s.in.Scan() {
		line := strings.TrimSpace(s.in.Text())
		if line == "" {
			continue
		}
		var msg rpcMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			s.logf("parse error: %v", err)
			continue
		}
		switch {
		case msg.Method != "":
			requests <- rpcRequest{JSONRPC: msg.JSONRPC, ID: msg.ID, Method: msg.Method, Params: msg.Params}
		case len(msg.ID) > 0:
			s.deliver(msg)
		}
	}
	close(requests)
	<-done
	return s.in.Err()
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
	Capabilities    struct {
		Elicitation *json.RawMessage `json:"elicitation"`
	} `json:"capabilities"`
}

func (s *Server) handle(req rpcRequest) {
	switch req.Method {
	case "initialize":
		var ip initializeParams
		_ = json.Unmarshal(req.Params, &ip)
		s.clientElicits = ip.Capabilities.Elicitation != nil
		version := protocolVersion
		if ip.ProtocolVersion != "" {
			version = ip.ProtocolVersion
		}
		s.reply(req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		})
		s.logf("initialized: protocol=%s clientElicitation=%v strict=%v", version, s.clientElicits, s.strict)
	case "notifications/initialized":
		// Notification: no response.
	case "ping":
		s.reply(req.ID, map[string]any{})
	case "tools/list":
		s.reply(req.ID, map[string]any{"tools": s.allTools()})
	case "tools/call":
		s.handleToolCall(req)
	default:
		if len(req.ID) > 0 {
			s.replyErr(req.ID, -32601, "method not found: "+req.Method)
		}
	}
}

func toolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "mint_token",
			"description": "Mint a short-lived Ed25519 dual-actor JWT binding an agent identity (sub) to a human principal (act_as).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id":    map[string]any{"type": "string", "description": "Unique agent identity"},
					"user_id":     map[string]any{"type": "string", "description": "Human principal (act_as)"},
					"scopes":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Allowed scopes"},
					"ttl_seconds": map[string]any{"type": "integer", "description": "Token lifetime in seconds", "default": 30},
				},
				"required": []string{"agent_id", "user_id"},
			},
		},
		{
			"name":        "list_providers",
			"description": "List the providers registered on the Nexus Gateway that access can be requested for.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "list_connections",
			"description": "List the provider connections the human has already established, with live status.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "request_access",
			"description": "Request access to a provider. Returns a consent URL the human must approve; the agent cannot self-grant. Poll connection_status afterward.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"provider": map[string]any{"type": "string", "description": "Provider name (e.g. github, google-drive)"},
					"scopes":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional OAuth scopes; defaults to the Gateway's registered set"},
				},
				"required": []string{"provider"},
			},
		},
		{
			"name":        "connection_status",
			"description": "Check whether a provider connection is active (consent completed).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"provider": map[string]any{"type": "string"}},
				"required":   []string{"provider"},
			},
		},
		{
			"name":        "get_credential",
			"description": "Return a short-lived access token for a provider. DENIED by default (secretless) — prefer using the tool through Nexus so the agent never holds the raw token.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"provider": map[string]any{"type": "string"}},
				"required":   []string{"provider"},
			},
		},
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolCall(req rpcRequest) {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.replyErr(req.ID, -32602, "invalid params: "+err.Error())
		return
	}

	provider := extractProvider(p.Arguments)

	// Decide with the policy engine when present, else fall back to the strict-mode flag.
	allowed, reason := s.authorizeToolProvider(p.Name, provider)
	s.recordTool(p.Name, provider, allowed, reason)
	if !allowed {
		s.logf("tool call %q denied: %s", p.Name, reason)
		s.toolResult(req.ID, true, "Tool execution denied by Nexus guardrail: "+reason)
		return
	}

	if up, ok := s.toolRoute[p.Name]; ok {
		s.callUpstream(req.ID, up, p.Name, p.Arguments)
		return
	}

	switch p.Name {
	case "mint_token":
		s.callMintToken(req.ID, p.Arguments)
	case "list_providers":
		s.callListProviders(req.ID)
	case "list_connections":
		s.callListConnections(req.ID)
	case "request_access":
		s.callRequestAccess(req.ID, p.Arguments)
	case "connection_status":
		s.callConnectionStatus(req.ID, p.Arguments)
	case "get_credential":
		s.callGetCredential(req.ID, p.Arguments)
	default:
		s.toolResult(req.ID, true, "unknown tool: "+p.Name)
	}
}

func extractProvider(args json.RawMessage) string {
	var a struct {
		Provider string `json:"provider"`
	}
	_ = json.Unmarshal(args, &a)
	return a.Provider
}

// authorizeTool authorizes a non-provider tool call.
func (s *Server) authorizeTool(name string) (bool, string) {
	return s.authorizeToolProvider(name, "")
}

// authorizeToolProvider resolves whether a (tool, provider) call may proceed, escalating HITL via
// elicitation. get_credential is sensitive: it is denied unless a policy rule explicitly permits it.
func (s *Server) authorizeToolProvider(name, provider string) (bool, string) {
	// Read-only broker tools reveal no secrets and take no action; always allow (still audited).
	switch name {
	case "list_providers", "list_connections", "connection_status":
		return true, "read-only broker tool"
	}
	if s.engine != nil {
		label := name
		if provider != "" {
			label = name + " (" + provider + ")"
		}
		req := policy.Request{SessionID: s.agentID + "|" + s.actAs, Tool: name, Provider: provider}
		dec := s.engine.Evaluate(req)
		switch dec.Action {
		case policy.ActionAllow:
			return true, dec.Reason
		case policy.ActionDeny:
			return false, dec.Reason
		case policy.ActionHITL:
			switch s.elicitDecision(fmt.Sprintf("Nexus guardrail: approve %q? (%s)", label, dec.Reason)) {
			case hitl.Once:
				return true, "approved once"
			case hitl.Session:
				s.engine.GrantSession(req)
				return true, "approved for session"
			case hitl.Always:
				s.engine.GrantSession(req)
				s.persistAllow(req)
				return true, "approved & persisted"
			default:
				return false, "denied at human-in-the-loop"
			}
		}
	}
	// No policy engine: handing out raw tokens is never permissive.
	if name == "get_credential" {
		return false, "get_credential requires an explicit policy allow rule (secretless by default)"
	}
	if s.strict {
		if s.elicitDecision(fmt.Sprintf("Nexus guardrail: approve MCP tool call %q?", name)).Allowed() {
			return true, "approved at human-in-the-loop"
		}
		return false, "denied at human-in-the-loop"
	}
	return true, "no policy (permissive)"
}

// persistAllow writes an "always allow" rule for this tool/provider via the configured callback.
func (s *Server) persistAllow(req policy.Request) {
	if s.persistRule == nil {
		return
	}
	s.persistRule(policy.Rule{Match: policy.Match{Tool: req.Tool, Provider: req.Provider}, Action: policy.ActionAllow})
}

func (s *Server) recordTool(name, provider string, allowed bool, reason string) {
	if s.auditlog == nil {
		return
	}
	outcome := "deny"
	if allowed {
		outcome = "allow"
	}
	target := "mcp:" + name
	if provider != "" {
		target += ":" + provider
	}
	_ = s.auditlog.Log(audit.Entry{
		Agent:    s.agentID,
		ActAs:    s.actAs,
		Tool:     name,
		Target:   target,
		Decision: outcome,
		Reason:   reason,
	})
}

func (s *Server) callMintToken(id, args json.RawMessage) {
	var a struct {
		AgentID string   `json:"agent_id"`
		UserID  string   `json:"user_id"`
		Scopes  []string `json:"scopes"`
		TTL     int      `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		s.toolResult(id, true, "invalid arguments: "+err.Error())
		return
	}
	if a.AgentID == "" {
		s.toolResult(id, true, "agent_id is required")
		return
	}
	if a.TTL <= 0 {
		a.TTL = 30
	}
	if len(a.Scopes) == 0 {
		a.Scopes = []string{"read"}
	}

	// act_as is bound to the server's logged-in principal, never the agent-supplied argument,
	// so an agent cannot forge the human identity it operates under.
	actAs := s.actAs
	if actAs == "" {
		actAs = a.UserID
	}
	scopes := capScopes(s.ceiling, a.Scopes)

	tok, err := s.signer.MintDualActorToken(a.AgentID, actAs, scopes, time.Duration(a.TTL)*time.Second)
	if err != nil {
		s.toolResult(id, true, "mint failed: "+err.Error())
		return
	}
	s.logf("minted token agent=%s act_as=%s ttl=%ds", a.AgentID, actAs, a.TTL)
	s.toolResult(id, false, tok)
}

// capScopes intersects requested scopes with a ceiling; an empty ceiling is unrestricted.
func capScopes(ceiling, requested []string) []string {
	if len(ceiling) == 0 {
		return requested
	}
	allow := make(map[string]bool, len(ceiling))
	for _, s := range ceiling {
		allow[s] = true
	}
	var out []string
	for _, s := range requested {
		if allow[s] {
			out = append(out, s)
		}
	}
	return out
}

// elicitDecision asks the client to collect a human approval decision via MCP elicitation, offering
// once / session / always / deny. It fails closed: no elicitation capability, decline, cancel, or
// timeout all deny.
func (s *Server) elicitDecision(message string) hitl.Decision {
	if !s.clientElicits {
		s.logf("client lacks elicitation capability; denying")
		return hitl.Deny
	}

	id := s.nextRequestID()
	ch := make(chan rpcMessage, 1)
	s.pendingMu.Lock()
	s.pending[string(id)] = ch
	s.pendingMu.Unlock()
	defer func() {
		s.pendingMu.Lock()
		delete(s.pending, string(id))
		s.pendingMu.Unlock()
	}()

	s.writeMsg(outgoing{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "elicitation/create",
		Params: map[string]any{
			"message": message,
			"requestedSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision": map[string]any{
						"type":        "string",
						"title":       "Decision",
						"description": "Approve once, for this session, always (save to policy), or deny",
						"enum":        []string{"once", "session", "always", "deny"},
					},
				},
				"required": []string{"decision"},
			},
		},
	})

	select {
	case resp := <-ch:
		if resp.Error != nil {
			s.logf("elicitation error: %s", resp.Error.Message)
			return hitl.Deny
		}
		var res struct {
			Action  string `json:"action"`
			Content struct {
				Decision string `json:"decision"`
			} `json:"content"`
		}
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			s.logf("elicitation decode error: %v", err)
			return hitl.Deny
		}
		if res.Action != "accept" {
			return hitl.Deny
		}
		switch res.Content.Decision {
		case "once":
			return hitl.Once
		case "session":
			return hitl.Session
		case "always":
			return hitl.Always
		default:
			return hitl.Deny
		}
	case <-time.After(2 * time.Minute):
		s.logf("elicitation timed out; denying")
		return hitl.Deny
	}
}

func (s *Server) deliver(msg rpcMessage) {
	s.pendingMu.Lock()
	ch, ok := s.pending[string(msg.ID)]
	s.pendingMu.Unlock()
	if ok {
		ch <- msg
		return
	}
	s.logf("unmatched response id=%s", string(msg.ID))
}

func (s *Server) nextRequestID() json.RawMessage {
	s.idMu.Lock()
	s.idSeq++
	id := s.idSeq
	s.idMu.Unlock()
	return json.RawMessage(strconv.Itoa(id))
}

func (s *Server) toolResult(id json.RawMessage, isErr bool, text string) {
	s.reply(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	})
}

func (s *Server) reply(id json.RawMessage, result any) {
	s.writeMsg(outgoing{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Server) replyErr(id json.RawMessage, code int, msg string) {
	s.writeMsg(outgoing{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func (s *Server) writeMsg(o outgoing) {
	b, err := json.Marshal(o)
	if err != nil {
		s.logf("marshal error: %v", err)
		return
	}
	s.writeMu.Lock()
	fmt.Fprintf(s.out, "%s\n", b)
	s.writeMu.Unlock()
}
