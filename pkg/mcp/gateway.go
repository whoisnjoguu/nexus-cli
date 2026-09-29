package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpstreamSpec describes a downstream MCP server the gateway spawns and gates.
type UpstreamSpec struct {
	Name    string            `yaml:"name" json:"name"`
	Command string            `yaml:"command" json:"command"`
	Args    []string          `yaml:"args" json:"args"`
	Env     map[string]string `yaml:"env" json:"env"`
}

// upstream is a live connection to a spawned MCP server, with synchronous id-routed requests.
type upstream struct {
	name   string
	prefix string
	cmd    *exec.Cmd
	stdin  *json.Encoder
	logf   func(string, ...any)

	writeMu sync.Mutex

	idMu  sync.Mutex
	idSeq int

	pendingMu sync.Mutex
	pending   map[string]chan rpcMessage

	tools []map[string]any // upstream tool defs, names rewritten with prefix
}

// startUpstreams spawns and initializes each configured upstream, aggregating their tools.
func (s *Server) startUpstreams(specs []UpstreamSpec) error {
	s.toolRoute = make(map[string]*upstream)
	for _, spec := range specs {
		if spec.Command == "" {
			return fmt.Errorf("upstream %q: command is required", spec.Name)
		}
		up, err := s.spawnUpstream(spec)
		if err != nil {
			return fmt.Errorf("upstream %q: %w", spec.Name, err)
		}
		s.upstreams = append(s.upstreams, up)
		for _, td := range up.tools {
			if name, ok := td["name"].(string); ok {
				s.toolRoute[name] = up
			}
		}
	}
	return nil
}

func (s *Server) spawnUpstream(spec UpstreamSpec) (*upstream, error) {
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Env = os.Environ()
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = os.Stderr

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	up := &upstream{
		name:    spec.Name,
		prefix:  spec.Name + "__",
		cmd:     cmd,
		stdin:   json.NewEncoder(stdinPipe),
		logf:    s.logf,
		pending: make(map[string]chan rpcMessage),
	}

	go up.readLoop(stdoutPipe)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := up.initialize(ctx); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	if err := up.loadTools(ctx); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	return up, nil
}

func (u *upstream) readLoop(r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg rpcMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if len(msg.ID) == 0 {
			continue // notification from upstream: ignored
		}
		u.pendingMu.Lock()
		ch, ok := u.pending[string(msg.ID)]
		u.pendingMu.Unlock()
		if ok {
			ch <- msg
		}
	}
}

func (u *upstream) initialize(ctx context.Context) error {
	_, err := u.call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "nexus-gateway", "version": serverVersion},
	})
	if err != nil {
		return err
	}
	return u.notify("notifications/initialized", map[string]any{})
}

func (u *upstream) loadTools(ctx context.Context) error {
	res, err := u.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return err
	}
	var parsed struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(res, &parsed); err != nil {
		return fmt.Errorf("parse tools/list: %w", err)
	}
	for _, td := range parsed.Tools {
		if name, ok := td["name"].(string); ok {
			td["name"] = u.prefix + name // namespace to avoid collisions across upstreams
		}
		u.tools = append(u.tools, td)
	}
	return nil
}

// call sends a request and blocks for the matching response.
func (u *upstream) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	u.idMu.Lock()
	u.idSeq++
	id := json.RawMessage(strconv.Itoa(u.idSeq))
	u.idMu.Unlock()

	ch := make(chan rpcMessage, 1)
	u.pendingMu.Lock()
	u.pending[string(id)] = ch
	u.pendingMu.Unlock()
	defer func() {
		u.pendingMu.Lock()
		delete(u.pending, string(id))
		u.pendingMu.Unlock()
	}()

	u.writeMu.Lock()
	err := u.stdin.Encode(outgoing{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	u.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("write to upstream %s: %w", u.name, err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("upstream %s error: %s", u.name, resp.Error.Message)
		}
		return resp.Result, nil
	}
}

func (u *upstream) notify(method string, params any) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	return u.stdin.Encode(outgoing{JSONRPC: "2.0", Method: method, Params: params})
}

// allTools returns the local tools plus every aggregated upstream tool.
func (s *Server) allTools() []map[string]any {
	out := toolDefs()
	for _, up := range s.upstreams {
		out = append(out, up.tools...)
	}
	return out
}

// callUpstream forwards an approved tool call to the owning upstream, stripping the namespace prefix.
func (s *Server) callUpstream(id json.RawMessage, up *upstream, prefixedName string, args json.RawMessage) {
	realName := strings.TrimPrefix(prefixedName, up.prefix)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var rawArgs any
	if len(args) > 0 {
		_ = json.Unmarshal(args, &rawArgs)
	}
	res, err := up.call(ctx, "tools/call", map[string]any{"name": realName, "arguments": rawArgs})
	if err != nil {
		s.toolResult(id, true, "upstream call failed: "+err.Error())
		return
	}
	s.reply(id, json.RawMessage(res))
}

// Close terminates all spawned upstream processes and the consent landing server.
func (s *Server) Close() {
	for _, up := range s.upstreams {
		if up.cmd != nil && up.cmd.Process != nil {
			_ = up.cmd.Process.Kill()
		}
	}
	if s.returnShutdown != nil {
		s.returnShutdown()
	}
}
