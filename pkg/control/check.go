package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/gate"
)

const (
	// maxCheckBodyBytes bounds a POST /v1/check body.
	maxCheckBodyBytes = 64 << 10
	// maxAsyncChecks bounds approvals tracked for polling (in flight plus recently finished).
	maxAsyncChecks = 1024
	// asyncResultTTL is how long a finished approval stays pollable.
	asyncResultTTL = 10 * time.Minute
)

// Checker decides tool calls for POST /v1/check. *gate.Gate implements it.
type Checker interface {
	Begin(c gate.Call) (gate.Result, *gate.Pending)
}

// CheckRequest is the body of POST /v1/check.
type CheckRequest struct {
	AgentID  string          `json:"agent_id,omitempty"`
	ActAs    string          `json:"act_as,omitempty"`
	Session  string          `json:"session,omitempty"`
	Token    string          `json:"token,omitempty"` // optional nexus JWT; authoritative for identity
	Tool     string          `json:"tool,omitempty"`
	Provider string          `json:"provider,omitempty"`
	Method   string          `json:"method,omitempty"`
	Host     string          `json:"host,omitempty"`
	Path     string          `json:"path,omitempty"`
	Scopes   []string        `json:"scopes,omitempty"`
	Args     json.RawMessage `json:"args,omitempty"`
	// Wait bounds how long the call blocks for a human. Empty blocks until decided (up to the
	// approval timeout); "0" returns "pending" at once; otherwise a duration (capped at 60s) after
	// which an undecided call returns "pending". Poll pending calls with GET /v1/check/{id}.
	Wait string `json:"wait,omitempty"`
}

// CheckResponse is the answer of POST /v1/check and GET /v1/check/{id}.
type CheckResponse struct {
	Decision   string `json:"decision"` // allow | deny | pending
	Reason     string `json:"reason,omitempty"`
	Rule       string `json:"rule,omitempty"`
	Source     string `json:"source,omitempty"` // policy | approve | default | guard
	ApprovalID string `json:"approval_id,omitempty"`
}

// Allowed reports whether the call may proceed.
func (r CheckResponse) Allowed() bool { return r.Decision == "allow" }

// checkState is the decision API's mutable state; its zero value has no checker (503).
type checkState struct {
	mu      sync.Mutex
	checker Checker
	async   map[string]*asyncCheck
}

type asyncCheck struct {
	p        *gate.Pending
	begun    gate.Result
	finished time.Time // zero while in flight; guarded by checkState.mu
}

// SetChecker enables POST /v1/check and GET /v1/check/{id}, answered by c (typically the
// *gate.Gate built over the process's policy engine, approver and audit log). Nil disables them.
func (s *Server) SetChecker(c Checker) {
	s.checks.mu.Lock()
	s.checks.checker = c
	s.checks.mu.Unlock()
}

func (s *Server) checker() Checker {
	s.checks.mu.Lock()
	defer s.checks.mu.Unlock()
	return s.checks.checker
}

func responseOf(r gate.Result) CheckResponse {
	return CheckResponse{Decision: r.Decision(), Reason: r.Reason, Rule: r.Rule, Source: r.Source, ApprovalID: r.ApprovalID}
}

func pendingResponse(r gate.Result) CheckResponse {
	return CheckResponse{Decision: "pending", Reason: r.Reason, Rule: r.Rule, Source: r.Source, ApprovalID: r.ApprovalID}
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	ck := s.checker()
	if ck == nil {
		writeError(w, http.StatusServiceUnavailable, "the decision API is not enabled on this endpoint")
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCheckBodyBytes)
	var body CheckRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return
	}
	call, err := body.call()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var wait time.Duration
	if body.Wait != "" {
		if wait, err = parseWait(body.Wait); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	res, p := ck.Begin(call)
	if p == nil {
		writeJSON(w, http.StatusOK, responseOf(res))
		return
	}
	if body.Wait == "" {
		// Block for the human; the approval timeout bounds this, not the server's write timeout.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		writeJSON(w, http.StatusOK, responseOf(p.Wait(r.Context())))
		return
	}
	if !s.trackAsync(p, res) {
		// Can't track it for polling: decide now rather than leave an unreachable prompt.
		writeError(w, http.StatusServiceUnavailable, "too many pending checks")
		go p.Wait(canceled())
		return
	}
	s.respondAsync(w, r, p, res, wait)
}

func (s *Server) handleCheckPoll(w http.ResponseWriter, r *http.Request) {
	if s.checker() == nil {
		writeError(w, http.StatusServiceUnavailable, "the decision API is not enabled on this endpoint")
		return
	}
	wait, err := parseWait(r.URL.Query().Get("wait"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.checks.mu.Lock()
	s.sweepAsyncLocked(time.Now())
	a := s.checks.async[r.PathValue("id")]
	s.checks.mu.Unlock()
	if a == nil {
		writeError(w, http.StatusNotFound, "unknown or expired check")
		return
	}
	s.respondAsync(w, r, a.p, a.begun, wait)
}

// respondAsync answers with the decision if it arrives within wait, else "pending" (202).
func (s *Server) respondAsync(w http.ResponseWriter, r *http.Request, p *gate.Pending, begun gate.Result, wait time.Duration) {
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-p.Done():
		case <-t.C:
		case <-r.Context().Done():
		case <-s.closing:
		}
	}
	select {
	case <-p.Done():
		writeJSON(w, http.StatusOK, responseOf(p.Result()))
	default:
		writeJSON(w, http.StatusAccepted, pendingResponse(begun))
	}
}

// trackAsync registers p for polling and resolves it in the background, bounded by the
// approval timeout and the server's lifetime. It reports false when the table is full.
func (s *Server) trackAsync(p *gate.Pending, begun gate.Result) bool {
	now := time.Now()
	s.checks.mu.Lock()
	s.sweepAsyncLocked(now)
	if len(s.checks.async) >= maxAsyncChecks {
		s.checks.mu.Unlock()
		return false
	}
	if s.checks.async == nil {
		s.checks.async = make(map[string]*asyncCheck)
	}
	a := &asyncCheck{p: p, begun: begun}
	s.checks.async[p.ID()] = a
	s.checks.mu.Unlock()

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-s.closing:
				cancel()
			case <-ctx.Done():
			}
		}()
		p.Wait(ctx)
		s.checks.mu.Lock()
		a.finished = time.Now()
		s.checks.mu.Unlock()
	}()
	return true
}

func (s *Server) sweepAsyncLocked(now time.Time) {
	for id, a := range s.checks.async {
		if !a.finished.IsZero() && now.Sub(a.finished) > asyncResultTTL {
			delete(s.checks.async, id)
		}
	}
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func (b CheckRequest) call() (gate.Call, error) {
	if b.Tool == "" && b.Method == "" && b.Host == "" {
		return gate.Call{}, errors.New("a check needs a tool, or an HTTP method/host")
	}
	c := gate.Call{
		AgentID:  b.AgentID,
		ActAs:    b.ActAs,
		Session:  b.Session,
		Token:    b.Token,
		Tool:     b.Tool,
		Provider: b.Provider,
		Method:   strings.ToUpper(b.Method),
		Host:     b.Host,
		Path:     b.Path,
		Scopes:   b.Scopes,
	}
	raw := []byte(strings.TrimSpace(string(b.Args)))
	if len(raw) > 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return gate.Call{}, errors.New("args must be a JSON object")
		}
		if err := json.Unmarshal(raw, &c.Args); err != nil {
			return gate.Call{}, fmt.Errorf("invalid args: %w", err)
		}
		c.RawArgs = raw
	}
	return c, nil
}

// Check asks the endpoint to authorize a call (POST /v1/check). With req.Wait empty it blocks
// until a human decides (up to the endpoint's approval timeout), so ctx should allow for that.
func (c *Client) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/v1/check", req)
	if err != nil {
		return CheckResponse{}, err
	}
	return decodeCheck(resp)
}

// CheckStatus polls a pending check (GET /v1/check/{id}), long-polling up to wait.
func (c *Client) CheckStatus(ctx context.Context, approvalID string, wait time.Duration) (CheckResponse, error) {
	if approvalID == "" || strings.ContainsAny(approvalID, "/?#") {
		return CheckResponse{}, fmt.Errorf("control: invalid approval id %q", approvalID)
	}
	path := "/v1/check/" + url.PathEscape(approvalID)
	if wait > 0 {
		path += "?wait=" + url.QueryEscape(wait.String())
	}
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return CheckResponse{}, err
	}
	return decodeCheck(resp)
}

func decodeCheck(resp *http.Response) (CheckResponse, error) {
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return CheckResponse{}, apiError(resp)
	}
	defer drain(resp)
	var out CheckResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return CheckResponse{}, fmt.Errorf("control: decode check: %w", err)
	}
	return out, nil
}
