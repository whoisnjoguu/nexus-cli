package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

// clientCaps records the optional capabilities a client advertised at initialize.
type clientCaps struct {
	elicitation bool
	sampling    bool
	roots       bool
}

// clientSession is one connected MCP client: the stdio host, or one Streamable HTTP session. Sessions
// share upstreams and the policy engine but each tracks its own capabilities, in-flight requests
// and server→client requests.
type clientSession struct {
	srv *Server
	id  string
	def sink // where unsolicited messages (list_changed, ...) go

	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	caps        clientCaps
	protocol    string
	initialized bool
	closed      bool
	idSeq       int
	pending     map[string]chan rpcMessage // server→client requests awaiting a response
	inflight    map[string]*inflightReq    // client→server requests being handled
	lastActive  time.Time
}

type inflightReq struct {
	cancel    context.CancelFunc
	cancelled bool // cancelled by the client: no response must be sent
}

var errSessionClosed = errors.New("mcp: client session closed")

func (s *Server) newSession(id string, def sink) *clientSession {
	ctx, cancel := context.WithCancel(s.baseCtx)
	ss := &clientSession{
		srv:        s,
		id:         id,
		def:        def,
		ctx:        ctx,
		cancel:     cancel,
		pending:    make(map[string]chan rpcMessage),
		inflight:   make(map[string]*inflightReq),
		lastActive: time.Now(),
	}
	s.sessMu.Lock()
	s.sessions[id] = ss
	s.sessMu.Unlock()
	return ss
}

// auditID identifies the session in the audit log without exposing a full HTTP session id.
func (ss *clientSession) auditID() string {
	if len(ss.id) > 12 {
		return "http:" + ss.id[:12]
	}
	return ss.id
}

func (ss *clientSession) capabilities() clientCaps {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.caps
}

func (ss *clientSession) touch() {
	ss.mu.Lock()
	ss.lastActive = time.Now()
	ss.mu.Unlock()
}

// begin registers an in-flight client request and returns its context and a completion func that
// reports whether the client cancelled it.
func (ss *clientSession) begin(id json.RawMessage) (context.Context, func() (cancelled bool)) {
	ctx, cancel := context.WithCancel(ss.ctx)
	inf := &inflightReq{cancel: cancel}
	key := idKey(id)
	ss.mu.Lock()
	ss.inflight[key] = inf
	ss.lastActive = time.Now()
	ss.mu.Unlock()
	return ctx, func() bool {
		ss.mu.Lock()
		if ss.inflight[key] == inf {
			delete(ss.inflight, key)
		}
		c := inf.cancelled
		ss.mu.Unlock()
		cancel()
		return c
	}
}

// cancelRequest handles notifications/cancelled from the client.
func (ss *clientSession) cancelRequest(id json.RawMessage) bool {
	ss.mu.Lock()
	inf, ok := ss.inflight[idKey(id)]
	if ok {
		inf.cancelled = true
	}
	ss.mu.Unlock()
	if ok {
		inf.cancel()
	}
	return ok
}

func (ss *clientSession) nextID() json.RawMessage {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.idSeq++
	return json.RawMessage(strconv.Itoa(ss.idSeq))
}

// request sends a server→client request on out and waits for the client's response. If ctx ends
// first the client is told to cancel it.
func (ss *clientSession) request(ctx context.Context, out sink, method string, params any) (rpcMessage, error) {
	id := ss.nextID()
	key := idKey(id)
	ch := make(chan rpcMessage, 1)
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return rpcMessage{}, errSessionClosed
	}
	ss.pending[key] = ch
	ss.mu.Unlock()
	defer func() {
		ss.mu.Lock()
		delete(ss.pending, key)
		ss.mu.Unlock()
	}()

	if err := out.send(outgoing{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
		return rpcMessage{}, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-ss.ctx.Done():
		return rpcMessage{}, errSessionClosed
	case <-ctx.Done():
		if ss.ctx.Err() != nil {
			return rpcMessage{}, errSessionClosed
		}
		_ = out.send(notification("notifications/cancelled", map[string]any{"requestId": id, "reason": "request no longer needed"}))
		return rpcMessage{}, ctx.Err()
	}
}

// deliver routes a client response to the waiting server→client request.
func (ss *clientSession) deliver(msg rpcMessage) {
	ss.mu.Lock()
	ch, ok := ss.pending[idKey(msg.ID)]
	ss.mu.Unlock()
	if !ok {
		ss.srv.logf("unmatched response id=%s", string(msg.ID))
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

// close cancels everything in flight and unregisters the session.
func (ss *clientSession) close() {
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return
	}
	ss.closed = true
	ss.mu.Unlock()
	ss.cancel()
	s := ss.srv
	s.sessMu.Lock()
	if s.sessions[ss.id] == ss {
		delete(s.sessions, ss.id)
	}
	s.sessMu.Unlock()
	s.subMu.Lock()
	for uri, subs := range s.subs {
		delete(subs, ss)
		if len(subs) == 0 {
			delete(s.subs, uri)
		}
	}
	s.subMu.Unlock()
	if c, ok := ss.def.(interface{ close() }); ok {
		c.close()
	}
}

func (ss *clientSession) isClosed() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.closed
}

// relation ties upstream traffic to the client request that caused it, so progress, sampling and
// elicitation reach the right client on the right stream.
type relation struct {
	sess *clientSession
	out  sink
}

// liveSessions returns initialized, open sessions, most recently active first.
func (s *Server) liveSessions() []*clientSession {
	s.sessMu.Lock()
	var out []*clientSession
	for _, ss := range s.sessions {
		out = append(out, ss)
	}
	s.sessMu.Unlock()
	var live []*clientSession
	for _, ss := range out {
		ss.mu.Lock()
		ok := ss.initialized && !ss.closed
		ss.mu.Unlock()
		if ok {
			live = append(live, ss)
		}
	}
	for i := 1; i < len(live); i++ {
		for j := i; j > 0 && live[j].lastActiveAt().After(live[j-1].lastActiveAt()); j-- {
			live[j], live[j-1] = live[j-1], live[j]
		}
	}
	return live
}

func (ss *clientSession) lastActiveAt() time.Time {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.lastActive
}

// broadcast sends an unsolicited notification to every live session.
func (s *Server) broadcast(method string, params any) {
	for _, ss := range s.liveSessions() {
		if err := ss.def.send(notification(method, params)); err != nil {
			s.logf("notify %s to session %s: %v", method, ss.id, err)
		}
	}
}
