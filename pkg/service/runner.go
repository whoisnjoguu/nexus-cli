package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// Runner executes platform commands. Tests substitute a fake that records argv.
type Runner interface {
	// Output runs the command and returns its combined stdout+stderr. A non-zero exit returns the
	// output together with an error.
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
	// Stream runs the command with its output connected to w (e.g. `journalctl -f`).
	Stream(ctx context.Context, w io.Writer, name string, args ...string) error
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Output implements Runner.
func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	var buf bytes.Buffer
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	return buf.Bytes(), err
}

// Stream implements Runner.
func (ExecRunner) Stream(ctx context.Context, w io.Writer, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdout, c.Stderr = w, w
	return c.Run()
}

// run executes argv and folds the command's output into the error.
func run(ctx context.Context, r Runner, argv []string) error {
	out, err := r.Output(ctx, argv[0], argv[1:]...)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, msg)
		}
		return fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

func runAll(ctx context.Context, r Runner, cmds [][]string) error {
	for _, c := range cmds {
		if err := run(ctx, r, c); err != nil {
			return err
		}
	}
	return nil
}

// ShellJoin renders argv for display as a POSIX shell command line.
func ShellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = shellQuote(a)
	}
	return strings.Join(out, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
