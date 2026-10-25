package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// upstreamTransportHook, when set (tests only), replaces the proxy's upstream transport in dev/run.
var upstreamTransportHook http.RoundTripper

// exitCodeError carries a child process exit status out of a command so main can exit with it
// without printing a generic error.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// ExitCode reports the exit status a command asked to terminate with (e.g. `run` propagating its
// child's status). ok is false for ordinary errors.
func ExitCode(err error) (code int, ok bool) {
	var e exitCodeError
	if errors.As(err, &e) {
		return e.code, true
	}
	return 0, false
}

// resolveMITM maps a --mitm mode to a CA: auto uses an existing CA at ca.DefaultDir() (nil when
// none exists), on loads or creates it, off disables interception.
func resolveMITM(mode string) (*ca.CA, error) {
	switch mode {
	case "off":
		return nil, nil
	case "on", "auto":
	default:
		return nil, fmt.Errorf("--mitm must be auto, on or off (got %q)", mode)
	}
	dir, err := ca.DefaultDir()
	if err != nil {
		return nil, err
	}
	if mode == "on" {
		return ca.LoadOrCreate(dir)
	}
	c, err := ca.Load(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return c, err
}

// loadPolicyOrDefault returns the policy in path, or the safe-tier default when the file is absent.
func loadPolicyOrDefault(path string) (pol policy.Policy, agent string, exists bool, err error) {
	cfg, exists, err := loadConfig(path)
	if err != nil {
		return policy.Policy{}, "", false, err
	}
	if !exists {
		return policy.DefaultPolicy(), "", false, nil
	}
	return cfg.Policy, cfg.Agent, true, nil
}

// policyScopes returns the sorted union of every scope required by the policy's rules.
func policyScopes(p policy.Policy) []string {
	set := map[string]bool{}
	for _, r := range p.Tools {
		if s := strings.TrimSpace(r.Scope); s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// splitList splits a comma-separated flag value, dropping blanks.
func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// localActor returns "<os user>@<hostname>" as an unverified fallback principal.
func localActor() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		name = os.Getenv("USER")
	}
	if name == "" {
		name = os.Getenv("USERNAME")
	}
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:] // DOMAIN\user on Windows
	}
	if name == "" {
		name = "unknown"
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	return name + "@" + host
}

// absPath returns an absolute form of p, or p itself if that fails.
func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
