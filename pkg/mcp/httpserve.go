package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HTTPOptions configures the Streamable HTTP server.
type HTTPOptions struct {
	// Token is the required bearer token (Authorization: Bearer <token>). Must not be empty.
	Token string
	// Path is the single MCP endpoint (default "/mcp").
	Path string
	// AllowedHosts are extra Host header values (hostnames, without port) accepted besides
	// loopback names. Needed when binding a non-loopback address.
	AllowedHosts []string
	// MaxSessions caps concurrent sessions (default 64).
	MaxSessions int
	// IdleTimeout closes sessions without activity for this long (default 30m).
	IdleTimeout time.Duration
}

const maxHTTPBody = 16 << 20

// NewSessionID returns a cryptographically random identifier (also used for bearer tokens).
func NewSessionID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

type httpHandler struct {
	s    *Server
	opts HTTPOptions

	mu      sync.Mutex
	streams map[string]bool // sessions with an attached GET stream
}

// HTTPHandler serves the gateway over MCP Streamable HTTP. Every session shares the server's
// upstreams and policy engine but has its own client capabilities.
func (s *Server) HTTPHandler(opts HTTPOptions) http.Handler {
	if opts.Path == "" {
		opts.Path = "/mcp"
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 64
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Minute
	}
	return &httpHandler{s: s, opts: opts, streams: make(map[string]bool)}
}

// ServeStreamableHTTP serves the gateway on ln until ctx ends.
func (s *Server) ServeStreamableHTTP(ctx context.Context, ln net.Listener, opts HTTPOptions) error {
	if opts.Token == "" {
		return errors.New("mcp: HTTP serving requires a bearer token")
	}
	h := s.HTTPHandler(opts).(*httpHandler)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	s.logf("serving MCP over Streamable HTTP at http://%s%s", ln.Addr(), h.opts.Path)

	stopReaper := make(chan struct{})
	go h.reap(stopReaper)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case err := <-errCh:
		close(stopReaper)
		return err
	case <-ctx.Done():
	}
	close(stopReaper)
	h.closeAll()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	return nil
}

func (h *httpHandler) reap(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		for _, ss := range h.httpSessions() {
			if time.Since(ss.lastActiveAt()) > h.opts.IdleTimeout {
				h.s.logf("closing idle HTTP session %s", ss.id[:8])
				ss.close()
			}
		}
	}
}

func (h *httpHandler) httpSessions() []*clientSession {
	h.s.sessMu.Lock()
	defer h.s.sessMu.Unlock()
	var out []*clientSession
	for _, ss := range h.s.sessions {
		if _, ok := ss.def.(*queueSink); ok {
			out = append(out, ss)
		}
	}
	return out
}

func (h *httpHandler) closeAll() {
	for _, ss := range h.httpSessions() {
		ss.close()
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// checkRequest enforces the DNS-rebinding (Host), cross-origin (Origin) and auth (bearer) rules.
func (h *httpHandler) checkRequest(w http.ResponseWriter, r *http.Request) bool {
	host := hostOnly(r.Host)
	allowed := isLoopbackHost(host)
	for _, a := range h.opts.AllowedHosts {
		if strings.EqualFold(a, host) {
			allowed = true
		}
	}
	if !allowed {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !isLoopbackHost(u.Hostname()) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return false
		}
	}
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(tok)), []byte(h.opts.Token)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="nexus-mcp"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.opts.Path {
		http.NotFound(w, r)
		return
	}
	if !h.checkRequest(w, r) {
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !isSupportedVersion(v) {
		http.Error(w, "unsupported MCP-Protocol-Version", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.post(w, r)
	case http.MethodGet:
		h.get(w, r)
	case http.MethodDelete:
		ss := h.lookup(w, r)
		if ss == nil {
			return
		}
		ss.close()
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *httpHandler) lookup(w http.ResponseWriter, r *http.Request) *clientSession {
	id := r.Header.Get("Mcp-Session-Id")
	if id == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return nil
	}
	h.s.sessMu.Lock()
	ss := h.s.sessions[id]
	h.s.sessMu.Unlock()
	if ss == nil || ss.isClosed() {
		http.Error(w, "unknown session", http.StatusNotFound)
		return nil
	}
	if _, ok := ss.def.(*queueSink); !ok {
		http.Error(w, "unknown session", http.StatusNotFound)
		return nil
	}
	return ss
}

func writeJSONError(w http.ResponseWriter, status int, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(outgoing{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: newErr(code, msg)})
}

func (h *httpHandler) post(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBody+1))
	if err != nil || len(body) > maxHTTPBody {
		writeJSONError(w, http.StatusBadRequest, -32700, "unreadable or oversized body")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		writeJSONError(w, http.StatusBadRequest, codeInvalidRequest, "JSON-RPC batches are not supported")
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err != nil || msg.JSONRPC != "2.0" {
		writeJSONError(w, http.StatusBadRequest, -32700, "parse error")
		return
	}

	var ss *clientSession
	if msg.Method == "initialize" && msg.isRequest() {
		if r.Header.Get("Mcp-Session-Id") != "" {
			writeJSONError(w, http.StatusBadRequest, codeInvalidRequest, "initialize must not carry a session id")
			return
		}
		if len(h.httpSessions()) >= h.opts.MaxSessions {
			writeJSONError(w, http.StatusServiceUnavailable, codeServerError, "too many sessions")
			return
		}
		ss = h.s.newSession(NewSessionID(), newQueueSink())
		w.Header().Set("Mcp-Session-Id", ss.id)
		h.s.status.kick()
	} else if ss = h.lookup(w, r); ss == nil {
		return
	}

	if !msg.isRequest() {
		h.s.process(ss, msg, ss.def)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	select {
	case h.s.sem <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	defer func() { <-h.s.sem }()
	ps := &postSink{w: w, id: idKey(msg.ID)}
	ps.flusher, _ = w.(http.Flusher)
	// A client that disconnects mid-request has abandoned it: cancel it like notifications/cancelled.
	stop := context.AfterFunc(r.Context(), func() { ss.cancelRequest(msg.ID) })
	h.s.process(ss, msg, ps)
	stop()
	ps.finish()
}

// postSink streams the messages belonging to one POSTed request back on its HTTP response: a
// plain JSON body when only the response is sent, upgrading to SSE when interim messages
// (progress, elicitation, sampling...) must be delivered first.
type postSink struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	id      string
	sse     bool
	done    bool
	evSeq   int
}

var errStreamClosed = errors.New("mcp: response stream closed")

func (p *postSink) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	final := false
	if o, ok := v.(outgoing); ok && o.Method == "" && idKey(o.ID) == p.id {
		final = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return errStreamClosed
	}
	if final && !p.sse {
		p.w.Header().Set("Content-Type", "application/json")
		p.w.WriteHeader(http.StatusOK)
		_, err = p.w.Write(append(b, '\n'))
		p.done = true
		return err
	}
	if !p.sse {
		if p.flusher == nil {
			return errStreamClosed
		}
		p.w.Header().Set("Content-Type", "text/event-stream")
		p.w.Header().Set("Cache-Control", "no-cache")
		p.w.WriteHeader(http.StatusOK)
		p.sse = true
	}
	p.evSeq++
	if _, err = fmt.Fprintf(p.w, "id: %d\nevent: message\ndata: %s\n\n", p.evSeq, b); err != nil {
		return err
	}
	p.flusher.Flush()
	if final {
		p.done = true
	}
	return nil
}

// finish ends the response; if nothing was written (e.g. the client cancelled) it sends 202.
func (p *postSink) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.done && !p.sse {
		p.w.WriteHeader(http.StatusAccepted)
	}
	p.done = true
}

// queueSink buffers a session's unsolicited messages for its GET SSE stream.
type queueSink struct {
	ch       chan []byte
	closed   chan struct{}
	closeOne sync.Once
}

func newQueueSink() *queueSink {
	return &queueSink{ch: make(chan []byte, 256), closed: make(chan struct{})}
}

func (q *queueSink) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	select {
	case <-q.closed:
		return errStreamClosed
	default:
	}
	select {
	case q.ch <- b:
		return nil
	default:
		return errors.New("mcp: session stream backlog full; message dropped")
	}
}

func (q *queueSink) close() { q.closeOne.Do(func() { close(q.closed) }) }

func (h *httpHandler) get(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		http.Error(w, "Accept must include text/event-stream", http.StatusNotAcceptable)
		return
	}
	ss := h.lookup(w, r)
	if ss == nil {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	if h.streams[ss.id] {
		h.mu.Unlock()
		http.Error(w, "a stream is already open for this session", http.StatusConflict)
		return
	}
	h.streams[ss.id] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.streams, ss.id)
		h.mu.Unlock()
	}()

	q := ss.def.(*queueSink)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 2000\n\n")
	fl.Flush()
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	seq := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-q.closed:
			return
		case <-keep.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
		case b := <-q.ch:
			seq++
			ss.touch()
			if _, err := fmt.Fprintf(w, "id: %d\nevent: message\ndata: %s\n\n", seq, b); err != nil {
				return
			}
			fl.Flush()
		}
	}
}
