package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamSpec describes a downstream MCP server the gateway connects to and gates: either a
// local command spoken to over stdio, or a remote Streamable HTTP endpoint.
type UpstreamSpec struct {
	Name    string            `yaml:"name" json:"name"`
	Command string            `yaml:"command,omitempty" json:"command,omitempty"`
	Args    []string          `yaml:"args,omitempty" json:"args,omitempty"`
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Cwd     string            `yaml:"cwd,omitempty" json:"cwd,omitempty"`
	// URL selects the Streamable HTTP transport; Headers are sent with every request and may
	// reference environment variables as ${VAR} so tokens stay out of nexus.yaml.
	URL      string            `yaml:"url,omitempty" json:"url,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Disabled bool              `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	// NoRestart leaves this upstream down when it exits instead of restarting it with backoff.
	NoRestart bool `yaml:"no_restart,omitempty" json:"no_restart,omitempty"`
}

func (spec UpstreamSpec) validate() error {
	switch {
	case spec.Name == "":
		return errors.New("upstream: name is required")
	case strings.Contains(spec.Name, "__"):
		return fmt.Errorf("upstream %q: name must not contain %q", spec.Name, "__")
	case spec.Command == "" && spec.URL == "":
		return fmt.Errorf("upstream %q: command or url is required", spec.Name)
	case spec.Command != "" && spec.URL != "":
		return fmt.Errorf("upstream %q: set either command or url, not both", spec.Name)
	}
	return nil
}

func (spec UpstreamSpec) transportName() string {
	if spec.URL != "" {
		return "http"
	}
	return "stdio"
}

// transport moves JSON-RPC frames to and from one upstream connection.
type transport interface {
	start(ctx context.Context) error
	// send writes one frame. For HTTP it may block while the response stream is consumed.
	send(ctx context.Context, msg outgoing) error
	// initialized is called after a successful initialize with the negotiated protocol version.
	initialized(protocolVersion string)
	done() <-chan struct{}
	err() error
	close()
}

// Upstream states.
const (
	stateStarting   = "starting"
	stateUp         = "up"
	stateRestarting = "restarting"
	stateDown       = "down"
	stateDisabled   = "disabled"
	stateStopped    = "stopped"
)

// upstream is a supervised connection to one MCP server.
type upstream struct {
	srv    *Server
	spec   UpstreamSpec
	name   string
	prefix string
	index  int

	mu       sync.Mutex
	t        transport
	state    string
	tools    []map[string]any
	caps     map[string]any
	protocol string
	restarts int
	failures int
	lastErr  string
	upSince  time.Time
	since    time.Time
	closing  bool
	pending  map[string]*upCall
	relays   map[string]context.CancelFunc
	inflight []*relation // relations of in-flight calls, newest last

	idSeq atomic.Int64
}

type upCall struct {
	ch chan rpcMessage
}

// newTransport is swappable in tests.
var newTransport = func(s *Server, spec UpstreamSpec, onMsg func(rpcMessage)) transport {
	if spec.URL != "" {
		return newHTTPTransport(spec, onMsg, s.logf)
	}
	return newStdioTransport(spec, onMsg, s.logf)
}

// startUpstreams connects every configured upstream concurrently. Failures are logged and retried
// in the background so one broken server never takes the gateway down.
func (s *Server) startUpstreams(specs []UpstreamSpec) {
	for i, spec := range specs {
		u := &upstream{
			srv:     s,
			spec:    spec,
			name:    spec.Name,
			prefix:  spec.Name + "__",
			index:   i,
			state:   stateStarting,
			since:   time.Now(),
			pending: make(map[string]*upCall),
			relays:  make(map[string]context.CancelFunc),
		}
		if spec.Disabled {
			u.state = stateDisabled
		}
		s.upstreams = append(s.upstreams, u)
	}
	var wg sync.WaitGroup
	for _, u := range s.upstreams {
		if u.spec.Disabled {
			continue
		}
		wg.Add(1)
		go func(u *upstream) {
			defer wg.Done()
			if err := u.connect(); err != nil {
				s.logf("upstream %s failed to start: %v", u.name, err)
				u.afterFailure(err)
			}
		}(u)
	}
	wg.Wait()
	s.rebuildRoutes()
}

func (u *upstream) setState(st string) {
	if u.state != st {
		u.state = st
		u.since = time.Now()
	}
}

func (u *upstream) stateName() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state
}

func (u *upstream) isUp() bool { return u.stateName() == stateUp }

func (u *upstream) hasCap(name string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.caps[name]
	return ok
}

func (u *upstream) subCap(name, sub string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	m, _ := u.caps[name].(map[string]any)
	v, _ := m[sub].(bool)
	return v
}

// connect starts a transport, initializes the session and loads the tool list.
func (u *upstream) connect() error {
	s := u.srv
	t := newTransport(s, u.spec, u.onMessage)
	ctx, cancel := context.WithTimeout(s.baseCtx, 60*time.Second)
	defer cancel()
	if err := t.start(ctx); err != nil {
		return err
	}
	u.mu.Lock()
	if u.closing {
		u.mu.Unlock()
		t.close()
		return errors.New("shutting down")
	}
	u.t = t
	u.mu.Unlock()

	fail := func(err error) error {
		t.close()
		u.mu.Lock()
		if u.t == t {
			u.t = nil
		}
		u.mu.Unlock()
		return err
	}

	res, err := u.callOn(ctx, t, "initialize", map[string]any{
		"protocolVersion": LatestProtocolVersion,
		"capabilities": map[string]any{
			"roots":       map[string]any{"listChanged": true},
			"sampling":    map[string]any{},
			"elicitation": map[string]any{},
		},
		"clientInfo": map[string]any{"name": "nexus-gateway", "version": s.version},
	}, nil)
	if err != nil {
		return fail(fmt.Errorf("initialize: %w", err))
	}
	var init struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
	}
	if err := json.Unmarshal(res, &init); err != nil {
		return fail(fmt.Errorf("parse initialize result: %w", err))
	}
	if init.ProtocolVersion == "" {
		init.ProtocolVersion = LatestProtocolVersion
	}
	t.initialized(init.ProtocolVersion)
	if err := t.send(ctx, notification("notifications/initialized", map[string]any{})); err != nil {
		return fail(fmt.Errorf("initialized notification: %w", err))
	}
	if init.Capabilities == nil {
		init.Capabilities = map[string]any{}
	}

	u.mu.Lock()
	u.caps = init.Capabilities
	u.protocol = init.ProtocolVersion
	u.mu.Unlock()

	var tools []map[string]any
	if _, ok := init.Capabilities["tools"]; ok {
		if tools, err = u.fetchTools(ctx, t); err != nil {
			return fail(err)
		}
	}

	u.mu.Lock()
	if u.closing || u.t != t {
		u.mu.Unlock()
		return fail(errors.New("shutting down"))
	}
	u.tools = tools
	u.setState(stateUp)
	u.upSince = time.Now()
	u.mu.Unlock()
	s.logf("upstream %s up (%s, protocol %s, %d tools)", u.name, u.spec.transportName(), init.ProtocolVersion, len(tools))
	go u.watch(t)
	s.status.kick()
	return nil
}

// fetchTools loads (and namespaces) the upstream's tools, following pagination.
func (u *upstream) fetchTools(ctx context.Context, t transport) ([]map[string]any, error) {
	var out []map[string]any
	cursor := ""
	for page := 0; page < 100; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		res, err := u.callOn(ctx, t, "tools/list", params, nil)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		var parsed struct {
			Tools      []map[string]any `json:"tools"`
			NextCursor string           `json:"nextCursor"`
		}
		if err := json.Unmarshal(res, &parsed); err != nil {
			return nil, fmt.Errorf("parse tools/list: %w", err)
		}
		for _, td := range parsed.Tools {
			if name, ok := td["name"].(string); ok {
				td["name"] = u.prefix + name // namespace to avoid collisions across upstreams
				out = append(out, td)
			}
		}
		if parsed.NextCursor == "" {
			break
		}
		cursor = parsed.NextCursor
	}
	return out, nil
}

// watch waits for the transport to die, fails its pending calls and schedules a restart.
func (u *upstream) watch(t transport) {
	<-t.done()
	err := t.err()
	if err == nil {
		err = errors.New("connection closed")
	}
	u.mu.Lock()
	if u.t != t {
		u.mu.Unlock()
		return
	}
	u.t = nil
	u.tools = nil
	if u.closing {
		u.setState(stateStopped)
		u.mu.Unlock()
		return
	}
	stable := time.Since(u.upSince) >= u.srv.stableAfter
	u.mu.Unlock()
	u.srv.logf("upstream %s exited: %v", u.name, err)
	if stable {
		u.mu.Lock()
		u.failures = 0
		u.mu.Unlock()
	}
	u.afterFailure(err)
	u.srv.toolsChanged()
}

// afterFailure records a failure and either schedules a restart or marks the upstream down.
func (u *upstream) afterFailure(err error) {
	u.mu.Lock()
	u.failures++
	u.lastErr = err.Error()
	if u.closing {
		u.setState(stateStopped)
		u.mu.Unlock()
		return
	}
	if u.srv.disableRestart || u.spec.NoRestart {
		u.setState(stateDown)
		u.mu.Unlock()
		u.srv.status.kick()
		return
	}
	u.setState(stateRestarting)
	u.mu.Unlock()
	u.srv.status.kick()
	go u.restartLoop()
}

// restartLoop retries with exponential backoff until the upstream is up again or has failed
// maxRestartFailures times in a row.
func (u *upstream) restartLoop() {
	s := u.srv
	backoff := s.restartMin
	for {
		u.mu.Lock()
		if u.failures >= s.maxRestartFailures {
			u.setState(stateDown)
			u.mu.Unlock()
			s.logf("upstream %s is down after %d consecutive failures (last: %s)", u.name, s.maxRestartFailures, u.lastErr)
			s.status.kick()
			return
		}
		u.mu.Unlock()

		timer := time.NewTimer(backoff)
		select {
		case <-s.baseCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		u.mu.Lock()
		u.restarts++
		u.mu.Unlock()
		s.logf("restarting upstream %s (backoff %s)", u.name, backoff)
		err := u.connect()
		if err == nil {
			s.toolsChanged()
			return
		}
		if s.baseCtx.Err() != nil {
			return
		}
		u.mu.Lock()
		u.failures++
		u.lastErr = err.Error()
		u.mu.Unlock()
		s.logf("upstream %s restart failed: %v", u.name, err)
		s.status.kick()
		backoff *= 2
		if backoff > s.restartMax {
			backoff = s.restartMax
		}
	}
}

func (u *upstream) shutdown() {
	u.mu.Lock()
	u.closing = true
	t := u.t
	u.mu.Unlock()
	if t != nil {
		t.close()
	}
	u.mu.Lock()
	if u.state != stateDisabled {
		u.setState(stateStopped)
	}
	u.mu.Unlock()
}

func (u *upstream) current() transport {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.state != stateUp {
		return nil
	}
	return u.t
}

var errUnavailable = errors.New("upstream unavailable")

// call forwards a request to the live transport, bounded by the per-call timeout.
func (u *upstream) call(ctx context.Context, method string, params any, rel *relation) (json.RawMessage, error) {
	t := u.current()
	if t == nil {
		return nil, fmt.Errorf("%w: %s is %s", errUnavailable, u.name, u.stateName())
	}
	ctx, cancel := context.WithTimeout(ctx, u.srv.callTimeout)
	defer cancel()
	return u.callOn(ctx, t, method, params, rel)
}

// callOn sends a request and waits for its response, the transport dying, or ctx ending — in which
// case the upstream is told to cancel.
func (u *upstream) callOn(ctx context.Context, t transport, method string, params any, rel *relation) (json.RawMessage, error) {
	id := json.RawMessage(strconv.FormatInt(u.idSeq.Add(1), 10))
	key := idKey(id)
	c := &upCall{ch: make(chan rpcMessage, 1)}
	u.mu.Lock()
	u.pending[key] = c
	if rel != nil {
		u.inflight = append(u.inflight, rel)
	}
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		delete(u.pending, key)
		if rel != nil {
			for i, r := range u.inflight {
				if r == rel {
					u.inflight = append(u.inflight[:i], u.inflight[i+1:]...)
					break
				}
			}
		}
		u.mu.Unlock()
	}()

	sendCtx, stopSend := context.WithCancel(ctx)
	defer stopSend()
	errc := make(chan error, 1)
	go func() { errc <- t.send(sendCtx, outgoing{JSONRPC: "2.0", ID: id, Method: method, Params: params}) }()

	for {
		select {
		case resp := <-c.ch:
			if resp.Error != nil {
				return nil, resp.Error
			}
			if resp.Result == nil {
				return json.RawMessage("{}"), nil
			}
			return resp.Result, nil
		case err := <-errc:
			if err != nil {
				// A response may have raced the error (e.g. stream closed right after it).
				select {
				case resp := <-c.ch:
					if resp.Error != nil {
						return nil, resp.Error
					}
					return resp.Result, nil
				default:
				}
				if ctx.Err() != nil {
					u.cancelUpstream(t, id, ctx.Err())
					return nil, u.ctxErr(ctx)
				}
				return nil, fmt.Errorf("upstream %s: %w", u.name, err)
			}
			errc = nil
		case <-t.done():
			terr := t.err()
			if terr == nil {
				terr = errors.New("connection closed")
			}
			return nil, fmt.Errorf("upstream %s exited: %v", u.name, terr)
		case <-ctx.Done():
			u.cancelUpstream(t, id, ctx.Err())
			return nil, u.ctxErr(ctx)
		}
	}
}

func (u *upstream) ctxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("upstream %s request timed out", u.name)
	}
	return ctx.Err()
}

func (u *upstream) cancelUpstream(t transport, id json.RawMessage, cause error) {
	reason := "cancelled by client"
	if errors.Is(cause, context.DeadlineExceeded) {
		reason = "timed out"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.send(ctx, notification("notifications/cancelled", map[string]any{"requestId": id, "reason": reason}))
}

func (u *upstream) notify(method string, params any) {
	t := u.current()
	if t == nil {
		return
	}
	ctx, cancel := context.WithTimeout(u.srv.baseCtx, 10*time.Second)
	defer cancel()
	_ = t.send(ctx, notification(method, params))
}

// reply answers an upstream-originated request.
func (u *upstream) reply(id json.RawMessage, result json.RawMessage, rerr *rpcError) {
	u.mu.Lock()
	t := u.t
	u.mu.Unlock()
	if t == nil {
		return
	}
	msg := outgoing{JSONRPC: "2.0", ID: id, Error: rerr}
	if rerr == nil {
		if result == nil {
			result = json.RawMessage("{}")
		}
		msg.Result = result
	}
	ctx, cancel := context.WithTimeout(u.srv.baseCtx, 30*time.Second)
	defer cancel()
	if err := t.send(ctx, msg); err != nil {
		u.srv.logf("reply to upstream %s: %v", u.name, err)
	}
}

// onMessage dispatches a frame received from the upstream.
func (u *upstream) onMessage(m rpcMessage) {
	switch {
	case m.isResponse():
		u.mu.Lock()
		c, ok := u.pending[idKey(m.ID)]
		u.mu.Unlock()
		if ok {
			select {
			case c.ch <- m:
			default:
			}
		}
	case m.isRequest():
		go u.handleServerRequest(m)
	case m.isNotification():
		u.handleNotification(m)
	}
}

// relation picks the client a server→client message from this upstream should go to: the most
// recent in-flight call's client (on that call's stream), else the most recently active session.
func (u *upstream) relation() *relation {
	u.mu.Lock()
	for i := len(u.inflight) - 1; i >= 0; i-- {
		r := u.inflight[i]
		if !r.sess.isClosed() {
			u.mu.Unlock()
			return r
		}
	}
	u.mu.Unlock()
	if live := u.srv.liveSessions(); len(live) > 0 {
		return &relation{sess: live[0], out: live[0].def}
	}
	return nil
}

func (u *upstream) handleNotification(m rpcMessage) {
	s := u.srv
	switch m.Method {
	case "notifications/tools/list_changed":
		go u.reloadTools()
	case "notifications/progress":
		s.forwardProgress(u, m.Params)
	case "notifications/message":
		params := decodeObject(m.Params)
		if params == nil {
			return
		}
		if _, ok := params["logger"]; !ok {
			params["logger"] = u.name
		}
		if rel := u.relation(); rel != nil {
			_ = rel.out.send(notification(m.Method, params))
		}
	case "notifications/resources/updated":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(m.Params, &p)
		s.notifySubscribers(p.URI, m.Params)
	case "notifications/resources/list_changed", "notifications/prompts/list_changed":
		s.broadcast(m.Method, map[string]any{})
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			u.mu.Lock()
			cancel := u.relays[idKey(p.RequestID)]
			u.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
	}
}

func (u *upstream) reloadTools() {
	t := u.current()
	if t == nil {
		return
	}
	ctx, cancel := context.WithTimeout(u.srv.baseCtx, 30*time.Second)
	defer cancel()
	tools, err := u.fetchTools(ctx, t)
	if err != nil {
		u.srv.logf("upstream %s: reload tools: %v", u.name, err)
		return
	}
	u.mu.Lock()
	u.tools = tools
	u.mu.Unlock()
	u.srv.toolsChanged()
}

// handleServerRequest relays an upstream→client request (sampling, elicitation, roots, ping, ...)
// to a client and the client's answer back with the upstream's original id.
func (u *upstream) handleServerRequest(m rpcMessage) {
	s := u.srv
	rel := u.relation()
	if rel == nil {
		if m.Method == "ping" {
			u.reply(m.ID, nil, nil)
			return
		}
		u.reply(m.ID, nil, newErr(codeServerError, "no MCP client is connected to the Nexus gateway"))
		return
	}
	caps := rel.sess.capabilities()
	need := map[string]bool{
		"sampling/createMessage": caps.sampling,
		"elicitation/create":     caps.elicitation,
		"roots/list":             caps.roots,
	}
	if ok, known := need[m.Method]; known && !ok {
		u.reply(m.ID, nil, newErr(codeMethodNotFound, "client does not support "+m.Method))
		return
	}

	ctx, cancel := context.WithTimeout(rel.sess.ctx, s.callTimeout)
	defer cancel()
	key := idKey(m.ID)
	u.mu.Lock()
	u.relays[key] = cancel
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		delete(u.relays, key)
		u.mu.Unlock()
	}()

	if m.Method == "sampling/createMessage" {
		rc := &reqCtx{ctx: ctx, sess: rel.sess, out: rel.out, method: m.Method, params: m.Params}
		preq := policyRequest("sampling/createMessage", u.name, decodeObject(m.Params))
		az := s.authorize(rc, preq)
		s.recordTool(rc, "sampling/createMessage", u.name, m.Params, az)
		if !az.allowed {
			s.logf("sampling request from %s denied: %s", u.name, az.reason)
			u.reply(m.ID, nil, newErr(codeUserRejected, "sampling request denied by Nexus guardrail: "+az.reason))
			return
		}
	}

	var params any
	if len(m.Params) > 0 {
		params = m.Params
	}
	resp, err := rel.sess.request(ctx, rel.out, m.Method, params)
	if err != nil {
		if m.Method == "ping" {
			u.reply(m.ID, nil, nil)
			return
		}
		u.reply(m.ID, nil, newErr(codeServerError, "relay to client failed: "+err.Error()))
		return
	}
	u.reply(m.ID, resp.Result, resp.Error)
}

// Status reports the state of every configured upstream.
func (s *Server) Status() []UpstreamStatus {
	out := make([]UpstreamStatus, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		u.mu.Lock()
		out = append(out, UpstreamStatus{
			Name:      u.name,
			Transport: u.spec.transportName(),
			State:     u.state,
			Tools:     len(u.tools),
			Restarts:  u.restarts,
			LastError: u.lastErr,
			Since:     u.since,
			Protocol:  u.protocol,
		})
		u.mu.Unlock()
	}
	return out
}
