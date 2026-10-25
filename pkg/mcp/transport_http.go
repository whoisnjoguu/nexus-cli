package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// httpTransport is the MCP Streamable HTTP client transport: every frame is POSTed to one
// endpoint; responses arrive as JSON or as an SSE stream; an optional GET SSE stream carries
// server-initiated messages.
type httpTransport struct {
	spec    UpstreamSpec
	onMsg   func(rpcMessage)
	logf    func(string, ...any)
	client  *http.Client
	headers map[string]string

	mu        sync.Mutex
	sessionID string
	protocol  string

	ctx      context.Context
	cancel   context.CancelFunc
	doneCh   chan struct{}
	doneOnce sync.Once
	errMu    sync.Mutex
	failErr  error
	getWG    sync.WaitGroup

	// reconnect tuning for the GET stream (tests shorten it)
	retryMin, retryMax time.Duration
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnvRefs replaces ${VAR} (only that form) with the environment value.
func expandEnvRefs(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		return os.Getenv(m[2 : len(m)-1])
	})
}

func newHTTPTransport(spec UpstreamSpec, onMsg func(rpcMessage), logf func(string, ...any)) *httpTransport {
	h := make(map[string]string, len(spec.Headers))
	for k, v := range spec.Headers {
		h[k] = expandEnvRefs(v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &httpTransport{
		spec:     spec,
		onMsg:    onMsg,
		logf:     logf,
		client:   &http.Client{},
		headers:  h,
		ctx:      ctx,
		cancel:   cancel,
		doneCh:   make(chan struct{}),
		retryMin: time.Second,
		retryMax: 30 * time.Second,
	}
}

func (t *httpTransport) start(context.Context) error { return nil }

func (t *httpTransport) fail(err error) {
	t.doneOnce.Do(func() {
		t.errMu.Lock()
		t.failErr = err
		t.errMu.Unlock()
		t.cancel()
		close(t.doneCh)
	})
}

func (t *httpTransport) done() <-chan struct{} { return t.doneCh }

func (t *httpTransport) err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.failErr
}

func (t *httpTransport) setHeaders(req *http.Request) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	t.mu.Lock()
	sid, proto := t.sessionID, t.protocol
	t.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if proto != "" {
		req.Header.Set("MCP-Protocol-Version", proto)
	}
}

func (t *httpTransport) initialized(version string) {
	t.mu.Lock()
	t.protocol = version
	t.mu.Unlock()
	t.getWG.Add(1)
	go t.getLoop()
}

// send POSTs one frame and consumes the response (JSON or SSE), dispatching every message in it.
func (t *httpTransport) send(ctx context.Context, msg outgoing) error {
	select {
	case <-t.doneCh:
		return fmt.Errorf("transport closed: %v", t.err())
	default:
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	// Abort the POST if the transport is closed while it streams.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.spec.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	t.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if msg.Method == "initialize" {
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			t.mu.Lock()
			t.sessionID = sid
			t.mu.Unlock()
		}
	}
	isRequest := msg.Method != "" && hasID(msg.ID)
	switch {
	case resp.StatusCode == http.StatusAccepted:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if isRequest {
			return errors.New("server accepted a request without responding")
		}
		return nil
	case resp.StatusCode == http.StatusNotFound && t.hasSession():
		err := errors.New("session expired (HTTP 404)")
		t.fail(err)
		return err
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	gotResponse := false
	deliver := func(data []byte) {
		for _, m := range decodeFrames(data) {
			if m.isResponse() && isRequest && idKey(m.ID) == idKey(msg.ID) {
				gotResponse = true
			}
			t.onMsg(m)
		}
	}
	switch mt {
	case "text/event-stream":
		err := readSSE(resp.Body, func(ev sseEvent) bool {
			if ev.data != "" {
				deliver([]byte(ev.data))
			}
			return !(isRequest && gotResponse)
		})
		if err != nil && !gotResponse {
			return err
		}
	default:
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(data)) > 0 {
			deliver(data)
		}
	}
	if isRequest && !gotResponse {
		return errors.New("response stream ended without a result")
	}
	return nil
}

func (t *httpTransport) hasSession() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessionID != ""
}

// decodeFrames parses a single JSON-RPC message or a batch array.
func decodeFrames(data []byte) []rpcMessage {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var batch []rpcMessage
		if json.Unmarshal(data, &batch) == nil {
			return batch
		}
		return nil
	}
	var m rpcMessage
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return []rpcMessage{m}
}

// getLoop keeps the optional server→client SSE stream open, resuming with Last-Event-ID.
func (t *httpTransport) getLoop() {
	defer t.getWG.Done()
	lastID := ""
	backoff := t.retryMin
	for t.ctx.Err() == nil {
		req, err := http.NewRequestWithContext(t.ctx, http.MethodGet, t.spec.URL, nil)
		if err != nil {
			return
		}
		t.setHeaders(req)
		req.Header.Set("Accept", "text/event-stream")
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		resp, err := t.client.Do(req)
		wait := backoff
		switch {
		case err != nil:
			if t.ctx.Err() != nil {
				return
			}
		case resp.StatusCode == http.StatusMethodNotAllowed:
			resp.Body.Close()
			return // server offers no GET stream
		case resp.StatusCode == http.StatusNotFound && t.hasSession():
			resp.Body.Close()
			t.fail(errors.New("session expired (HTTP 404 on GET stream)"))
			return
		case resp.StatusCode != http.StatusOK:
			resp.Body.Close()
		default:
			backoff = t.retryMin
			_ = readSSE(resp.Body, func(ev sseEvent) bool {
				if ev.id != "" {
					lastID = ev.id
				}
				if ev.retry > 0 {
					backoff = ev.retry
				}
				if ev.data != "" {
					for _, m := range decodeFrames([]byte(ev.data)) {
						t.onMsg(m)
					}
				}
				return true
			})
			resp.Body.Close()
			wait = backoff
		}
		timer := time.NewTimer(wait)
		select {
		case <-t.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > t.retryMax {
			backoff = t.retryMax
		}
	}
}

// close terminates the session (DELETE) and stops the GET stream.
func (t *httpTransport) close() {
	if t.hasSession() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, t.spec.URL, nil)
		if err == nil {
			t.setHeaders(req)
			if resp, err := t.client.Do(req); err == nil {
				resp.Body.Close()
			}
		}
		cancel()
	}
	t.fail(errors.New("transport closed"))
	t.getWG.Wait()
}

// sseEvent is one Server-Sent Event.
type sseEvent struct {
	id    string
	event string
	data  string
	retry time.Duration
}

// readSSE parses an event stream, calling fn per event until it returns false or the stream ends.
func readSSE(r io.Reader, fn func(sseEvent) bool) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var ev sseEvent
	var data []string
	hasData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil && line == "" {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if hasData || ev.retry > 0 || ev.id != "" {
				ev.data = strings.Join(data, "\n")
				if !fn(ev) {
					return nil
				}
			}
			ev, data, hasData = sseEvent{}, nil, false
			if err != nil {
				return nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			ev.id = value
		case "event":
			ev.event = value
		case "data":
			data = append(data, value)
			hasData = true
		case "retry":
			if ms, perr := strconv.Atoi(value); perr == nil && ms > 0 {
				ev.retry = time.Duration(ms) * time.Millisecond
			}
		}
		if err != nil {
			return nil
		}
	}
}
