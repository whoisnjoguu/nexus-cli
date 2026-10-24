package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// stdioTransport spawns an MCP server process and speaks newline-delimited JSON-RPC to it.
type stdioTransport struct {
	spec  UpstreamSpec
	onMsg func(rpcMessage)
	logf  func(string, ...any)

	cmd     *exec.Cmd
	stdin   io.WriteCloser
	writeMu sync.Mutex

	doneCh   chan struct{}
	doneOnce sync.Once
	errMu    sync.Mutex
	exitErr  error
}

func newStdioTransport(spec UpstreamSpec, onMsg func(rpcMessage), logf func(string, ...any)) *stdioTransport {
	return &stdioTransport{spec: spec, onMsg: onMsg, logf: logf, doneCh: make(chan struct{})}
}

func (t *stdioTransport) start(context.Context) error {
	cmd := exec.Command(t.spec.Command, t.spec.Args...)
	cmd.Env = os.Environ()
	for k, v := range t.spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = t.spec.Cwd
	cmd.Stderr = &prefixWriter{prefix: "[" + t.spec.Name + "] ", w: os.Stderr}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	// A plain os.Pipe (not StdoutPipe) lets Wait report the exit promptly without racing reads.
	stdout, pw, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		return err
	}
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = pw.Close()
		return err
	}
	_ = pw.Close()
	t.cmd = cmd
	t.stdin = stdin

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var msg rpcMessage
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				t.logf("upstream %s: unparseable output: %.200s", t.spec.Name, line)
				continue
			}
			t.onMsg(msg)
		}
	}()
	go func() {
		// Drain stdout first (up to a grace period) so a final response isn't lost, then reap.
		err := cmd.Wait()
		select {
		case <-readDone:
		case <-time.After(time.Second):
		}
		_ = stdout.Close()
		if err == nil {
			err = errors.New("process exited")
		}
		t.finish(err)
	}()
	return nil
}

func (t *stdioTransport) finish(err error) {
	t.doneOnce.Do(func() {
		t.errMu.Lock()
		t.exitErr = err
		t.errMu.Unlock()
		close(t.doneCh)
	})
}

func (t *stdioTransport) send(_ context.Context, msg outgoing) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	select {
	case <-t.doneCh:
		return fmt.Errorf("process exited: %w", t.err())
	default:
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err = t.stdin.Write(append(b, '\n'))
	return err
}

func (t *stdioTransport) initialized(string) {}

func (t *stdioTransport) done() <-chan struct{} { return t.doneCh }

func (t *stdioTransport) err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.exitErr
}

// close asks the server to exit by closing stdin, then kills it after a grace period.
func (t *stdioTransport) close() {
	if t.cmd == nil || t.cmd.Process == nil {
		return
	}
	t.writeMu.Lock()
	_ = t.stdin.Close()
	t.writeMu.Unlock()
	select {
	case <-t.doneCh:
	case <-time.After(2 * time.Second):
		_ = t.cmd.Process.Kill()
		<-t.doneCh
	}
}

// prefixWriter tags each line of an upstream's stderr with its name.
type prefixWriter struct {
	mu     sync.Mutex
	prefix string
	w      io.Writer
	buf    []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	for {
		i := strings.IndexByte(string(p.buf), '\n')
		if i < 0 {
			break
		}
		fmt.Fprintf(p.w, "%s%s\n", p.prefix, p.buf[:i])
		p.buf = p.buf[i+1:]
	}
	if len(p.buf) > 64*1024 {
		fmt.Fprintf(p.w, "%s%s\n", p.prefix, p.buf)
		p.buf = nil
	}
	return len(b), nil
}
