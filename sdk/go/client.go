package sdk

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

// Environment variables read by Connect. `nexus-cli run` sets them for the command it launches.
const (
	EnvControlURL   = "NEXUS_CONTROL_URL"   // e.g. http://127.0.0.1:53124
	EnvControlToken = "NEXUS_CONTROL_TOKEN" // bearer token of that control endpoint
	EnvToken        = "NEXUS_TOKEN"         // optional nexus JWT sent with every check
	EnvProxyURL     = "NEXUS_PROXY_URL"     // http://nexus:<jwt>@host:port; its password is a fallback token
)

// ErrNoDaemon is returned by Connect when no running nexus-cli endpoint is found.
var ErrNoDaemon = errors.New("nexus sdk: no running nexus-cli found (start 'nexus-cli dev', 'nexus-cli run' or 'nexus-cli mcp serve')")

// CheckRequest and CheckResponse are the wire types of POST /v1/check.
type (
	CheckRequest  = control.CheckRequest
	CheckResponse = control.CheckResponse
)

// DeniedError is returned by Require when a call is not allowed.
type DeniedError struct {
	Response CheckResponse
	Call     string
}

func (e *DeniedError) Error() string {
	if e.Response.Decision == "pending" {
		return fmt.Sprintf("nexus: %s is pending approval %s", e.Call, e.Response.ApprovalID)
	}
	return fmt.Sprintf("nexus denied %s: %s", e.Call, e.Response.Reason)
}

// ConnectOptions narrows endpoint discovery.
type ConnectOptions struct {
	Kind string // only endpoints of this kind: dev, run or mcp
	PID  int    // only the endpoint of this process
}

// Client asks a running nexus-cli (dev, run or mcp serve) to authorize calls through its control
// API, so taint tracking, one_time rules, session grants, approvals and the audit log are shared
// with everything else that process gates. It implements Gate, so it plugs into GateTransport.
type Client struct {
	ctl *control.Client

	// Defaults applied to checks that leave them empty.
	AgentID string
	ActAs   string
	Session string
	Token   string // nexus JWT; authoritative for identity when set
}

// NewClient returns a client for a known endpoint.
func NewClient(info control.Info) *Client { return &Client{ctl: control.NewClient(info)} }

// Connect finds a running endpoint: NEXUS_CONTROL_URL + NEXUS_CONTROL_TOKEN when set, else the
// newest live discovery file in $NEXUS_HOME/control (or ~/.nexus/control) matching opts. The
// client's Token defaults to NEXUS_TOKEN, else the token embedded in NEXUS_PROXY_URL.
func Connect(opts ConnectOptions) (*Client, error) {
	info, err := discover(opts)
	if err != nil {
		return nil, err
	}
	c := NewClient(info)
	c.Token = envToken()
	return c, nil
}

func discover(opts ConnectOptions) (control.Info, error) {
	if raw := os.Getenv(EnvControlURL); raw != "" {
		tok := os.Getenv(EnvControlToken)
		if tok == "" {
			return control.Info{}, fmt.Errorf("nexus sdk: %s is set but %s is empty", EnvControlURL, EnvControlToken)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.Host == "" {
			return control.Info{}, fmt.Errorf("nexus sdk: invalid %s %q (want http://host:port)", EnvControlURL, raw)
		}
		return control.Info{Addr: u.Host, Token: tok}, nil
	}
	live, err := control.Discover()
	if err != nil {
		return control.Info{}, err
	}
	for i := len(live) - 1; i >= 0; i-- { // newest first
		in := live[i]
		if (opts.Kind == "" || in.Kind == opts.Kind) && (opts.PID == 0 || in.PID == opts.PID) {
			return in, nil
		}
	}
	return control.Info{}, ErrNoDaemon
}

func envToken() string {
	if t := os.Getenv(EnvToken); t != "" {
		return t
	}
	if u, err := url.Parse(os.Getenv(EnvProxyURL)); err == nil && u.User != nil {
		if p, ok := u.User.Password(); ok {
			return p
		}
	}
	return ""
}

// Info describes the endpoint the client talks to.
func (c *Client) Info() control.Info { return c.ctl.Info() }

// Close releases idle connections.
func (c *Client) Close() { c.ctl.Close() }

// Check authorizes a call. With req.Wait empty it blocks until a human decides calls that need
// approval (up to the endpoint's approval timeout), so ctx should allow for that; otherwise an
// undecided call returns Decision "pending" with an ApprovalID to Poll.
func (c *Client) Check(ctx context.Context, req CheckRequest) (CheckResponse, error) {
	if req.AgentID == "" {
		req.AgentID = c.AgentID
	}
	if req.ActAs == "" {
		req.ActAs = c.ActAs
	}
	if req.Session == "" {
		req.Session = c.Session
	}
	if req.Token == "" {
		req.Token = c.Token
	}
	return c.ctl.Check(ctx, req)
}

// Poll returns the state of a pending check, long-polling up to wait (capped at 60s).
func (c *Client) Poll(ctx context.Context, approvalID string, wait time.Duration) (CheckResponse, error) {
	return c.ctl.CheckStatus(ctx, approvalID, wait)
}

// Require is Check that returns a *DeniedError unless the call is allowed.
func (c *Client) Require(ctx context.Context, req CheckRequest) error {
	res, err := c.Check(ctx, req)
	if err != nil {
		return err
	}
	if !res.Allowed() {
		name := req.Tool
		if name == "" {
			name = strings.TrimSpace(req.Method + " " + req.Host + req.Path)
		}
		return &DeniedError{Response: res, Call: name}
	}
	return nil
}

// Authorize implements Gate by asking the endpoint, blocking for approvals.
func (c *Client) Authorize(ctx context.Context, call ToolCall) (Decision, error) {
	res, err := c.Check(ctx, CheckRequest{
		AgentID: call.Agent,
		ActAs:   call.ActAs,
		Session: call.SessionID,
		Tool:    call.Tool,
		Method:  call.Method,
		Host:    call.Host,
		Path:    call.Path,
		Scopes:  call.Scopes,
		Args:    call.argsJSON(),
	})
	if err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: res.Allowed(), Reason: res.Reason}, nil
}

// Status reports the endpoint's status.
func (c *Client) Status(ctx context.Context) (control.Status, error) { return c.ctl.Status(ctx) }

// Approvals lists pending approval requests.
func (c *Client) Approvals(ctx context.Context) ([]hitl.Request, error) { return c.ctl.List(ctx, 0) }

// Decide answers a pending approval request.
func (c *Client) Decide(ctx context.Context, id string, d hitl.Decision) error {
	return c.ctl.Decide(ctx, id, d)
}
