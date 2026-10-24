package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

// ErrUnauthorized is returned when the endpoint rejects the token (e.g. a stale discovery file
// whose port was reused by another process).
var ErrUnauthorized = errors.New("control: unauthorized")

// Client talks to one control endpoint.
type Client struct {
	info Info
	hc   *http.Client

	mu      sync.Mutex
	version string // last queue version seen, echoed on long-polls
}

// NewClient returns a client for the endpoint described by info.
func NewClient(info Info) *Client {
	return &Client{
		info: info,
		hc: &http.Client{
			// Never route loopback control traffic (and its token) through an HTTP proxy.
			Transport: &http.Transport{
				Proxy:               nil,
				DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Info returns the endpoint description the client was built from.
func (c *Client) Info() Info { return c.info }

// Close releases idle connections.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+c.info.Addr+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.info.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		drain(resp)
		return nil, ErrUnauthorized
	}
	return resp, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

func apiError(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return fmt.Errorf("control: %s (HTTP %d)", e.Error, resp.StatusCode)
	}
	return fmt.Errorf("control: HTTP %d", resp.StatusCode)
}

// Status fetches the endpoint status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/status", nil)
	if err != nil {
		return Status{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Status{}, apiError(resp)
	}
	defer drain(resp)
	var st Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return Status{}, fmt.Errorf("control: decode status: %w", err)
	}
	return st, nil
}

// List returns the pending requests, oldest first. With wait > 0 it long-polls: it returns when
// the queue changes since this client's previous List call (or at once if it already has), or
// after wait (capped at 60s by the server).
func (c *Client) List(ctx context.Context, wait time.Duration) ([]hitl.Request, error) {
	path := "/v1/approvals"
	if wait > 0 {
		q := url.Values{}
		q.Set("wait", wait.String())
		c.mu.Lock()
		if c.version != "" {
			q.Set("since", c.version)
		}
		c.mu.Unlock()
		path += "?" + q.Encode()
	}
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	defer drain(resp)
	var out []hitl.Request
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("control: decode approvals: %w", err)
	}
	if v := resp.Header.Get(VersionHeader); v != "" {
		c.mu.Lock()
		c.version = v
		c.mu.Unlock()
	}
	return out, nil
}

// Decide submits a decision. Unknown or already-decided IDs yield an error wrapping
// hitl.ErrUnknownRequest.
func (c *Client) Decide(ctx context.Context, id string, d hitl.Decision) error {
	if d < hitl.Deny || d > hitl.Always {
		return fmt.Errorf("control: invalid decision %d", int(d))
	}
	if id == "" || strings.ContainsAny(id, "/?#") {
		return fmt.Errorf("control: invalid request id %q: %w", id, hitl.ErrUnknownRequest)
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/approvals/"+url.PathEscape(id), map[string]string{"decision": d.String()})
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		drain(resp)
		return nil
	case http.StatusNotFound:
		drain(resp)
		return fmt.Errorf("control: request %s: %w", id, hitl.ErrUnknownRequest)
	default:
		return apiError(resp)
	}
}

// pingTimeout bounds each liveness probe made by Discover.
const pingTimeout = 500 * time.Millisecond

// Discover returns the live control endpoints, oldest first. Discovery files whose endpoint is
// unreachable (or rejects its own token) are deleted; unreadable files are skipped.
func Discover() ([]Info, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	type cand struct {
		path string
		info Info
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var info Info
		if err := json.Unmarshal(b, &info); err != nil || info.Addr == "" || info.Token == "" {
			continue
		}
		cands = append(cands, cand{p, info})
	}

	live := make([]bool, len(cands))
	var wg sync.WaitGroup
	for i, c := range cands {
		wg.Add(1)
		go func(i int, c cand) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
			defer cancel()
			cl := NewClient(c.info)
			defer cl.Close()
			_, err := cl.Status(ctx)
			if err == nil {
				live[i] = true
				return
			}
			var ne net.Error
			if errors.Is(err, ErrUnauthorized) || isConnRefused(err) || (errors.As(err, &ne) && !ne.Timeout()) {
				_ = os.Remove(c.path)
			}
		}(i, c)
	}
	wg.Wait()

	var out []Info
	for i, c := range cands {
		if live[i] {
			out = append(out, c.info)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out, nil
}

func isConnRefused(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "dial"
}
