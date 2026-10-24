package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// policyRuntime is the live policy of a long-running command (dev, run, mcp serve): the engine
// built from the file, and the watcher that hot-reloads it.
type policyRuntime struct {
	Path   string
	Exists bool
	Config configFile // the parsed file (zero when !Exists)
	Policy policy.Policy
	Engine *policy.Engine
	Sum    string // sha256 of the loaded file ("" when !Exists)

	// PinFile is $NEXUS_HOME/policy.pin; AcceptChange (--accept-policy-change) re-pins a policy
	// whose hash differs from its pin instead of refusing it.
	PinFile      string
	AcceptChange bool
	// NoAudit suppresses the audit entries for pin decisions (--no-audit).
	NoAudit bool

	mu       sync.Mutex
	auditlog *audit.Logger
	watcher  *policy.Watcher
}

// runtimeOptions are the flags shared by dev, run and mcp serve.
type runtimeOptions struct {
	AcceptPolicyChange bool
	NoAudit            bool
}

// loadPolicyRuntime loads the policy at path strictly (or the safe-tier default when absent),
// verifies it against its pin and builds its engine with the built-in protected-path guard
// (workspace = cwd). It reads the file once, so the hash, the policy and the config agree.
func loadPolicyRuntime(path string, opts runtimeOptions) (*policyRuntime, error) {
	pinFile, err := policy.PinPath()
	if err != nil {
		return nil, err
	}
	rt := &policyRuntime{Path: path, PinFile: pinFile, AcceptChange: opts.AcceptPolicyChange, NoAudit: opts.NoAudit}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		rt.Policy = policy.DefaultPolicy()
	case err != nil:
		return nil, fmt.Errorf("read config %s: %w", path, err)
	default:
		cfg, perr := rt.parse(data)
		if perr != nil {
			return nil, perr
		}
		rt.Exists, rt.Config, rt.Policy, rt.Sum = true, cfg, cfg.Policy, policy.Sum(data)
	}
	rt.Engine = policy.NewEngine(rt.Policy)
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	rt.Engine.SetProtectedPaths(wd, rt.protectedPaths())
	return rt, nil
}

// protectedPaths are the files the guard keeps away from tool calls: the policy file, the nexus
// home (keys, pin, state, default audit log) and the configured audit log's directory.
func (rt *policyRuntime) protectedPaths() []string {
	paths := []string{rt.Path, rt.PinFile}
	if abs, err := filepath.Abs(rt.Path); err == nil {
		paths[0] = abs
	}
	if h, err := audit.Home(); err == nil {
		paths = append(paths, h)
	}
	if ap, err := rt.Config.Audit.ResolvedPath(); err == nil {
		paths = append(paths, filepath.Dir(ap))
	}
	return paths
}

// parse is the strict loader shared by startup and hot reload: pin check, then strict parsing
// and validation.
func (rt *policyRuntime) parse(data []byte) (configFile, error) {
	if err := rt.checkPin(data); err != nil {
		return configFile{}, err
	}
	return parseConfig(rt.Path, data)
}

// checkPin refuses content that differs from the policy's pin, or (with --accept-policy-change)
// accepts and re-pins it. Both outcomes are audited.
func (rt *policyRuntime) checkPin(data []byte) error {
	_, err := policy.CheckPin(rt.PinFile, rt.Path, data)
	var mm *policy.PinMismatchError
	if !errors.As(err, &mm) {
		return err
	}
	if rt.AcceptChange {
		if werr := policy.WritePin(rt.PinFile, rt.Path, mm.Actual); werr != nil {
			return fmt.Errorf("re-pin policy: %w", werr)
		}
		rt.auditPin("allow", "policy change accepted (--accept-policy-change); re-pinned", mm.Actual)
		return nil
	}
	rt.auditPin("deny", mm.Error(), mm.Actual)
	return err
}

// auditPin records a pin decision as tool "policy/pin". Before the configured log is open (the
// mismatched file's audit: section is untrusted) it goes to the default log.
func (rt *policyRuntime) auditPin(decision, reason, sum string) {
	if rt.NoAudit {
		return
	}
	entry := audit.Entry{
		Agent: "nexus-cli", ActAs: "nexus-cli", Tool: "policy/pin",
		Target: rt.Path + "#sha256:" + policy.ShortSum(sum), Decision: decision, Reason: reason,
	}
	rt.mu.Lock()
	l := rt.auditlog
	rt.mu.Unlock()
	if l != nil {
		_ = l.Log(entry)
		return
	}
	path, err := audit.DefaultPath()
	if err != nil {
		return
	}
	if l, err = audit.Open(path); err == nil {
		_ = l.Log(entry)
		_ = l.Close()
	}
}

// persistState makes single-use tokens, one_time consumption and taints survive restarts (and
// shared between nexus-cli processes) via $NEXUS_HOME/state/{jti,sessions}.json. With ephemeral
// (--ephemeral-state) everything stays in memory. It returns the replay guard to use.
func (rt *policyRuntime) persistState(ephemeral bool) (*jwt.ReplayGuard, error) {
	if ephemeral {
		return jwt.NewReplayGuard(), nil
	}
	jp, err := jwt.DefaultReplayStatePath()
	if err != nil {
		return nil, err
	}
	replay, err := jwt.NewPersistentReplayGuard(jp)
	if err != nil {
		return nil, err
	}
	sp, err := policy.DefaultSessionStatePath()
	if err != nil {
		return nil, err
	}
	st, err := policy.NewFileStateStore(sp)
	if err != nil {
		return nil, err
	}
	rt.Engine.SetStateStore(st)
	return replay, nil
}

// openAudit opens the audit log configured by the loaded file's audit: section.
func (rt *policyRuntime) openAudit() (*audit.Logger, string, error) {
	l, path, err := openAuditConfig(rt.Config)
	if err == nil {
		rt.mu.Lock()
		rt.auditlog = l
		rt.mu.Unlock()
	}
	return l, path, err
}

// watch starts hot reload of the policy file. auditlog may be nil; noSignal disables SIGHUP.
func (rt *policyRuntime) watch(auditlog *audit.Logger, stderr io.Writer, noSignal bool) {
	var al policy.AuditLogger
	if auditlog != nil {
		al = auditlog
	}
	rt.watcher = policy.NewWatcher(policy.WatcherConfig{
		Path:       rt.Path,
		Engine:     rt.Engine,
		InitialSum: rt.Sum,
		Audit:      al,
		Stderr:     stderr,
		NoSignal:   noSignal,
		Deps:       []string{rt.PinFile},
		Load: func(data []byte) (policy.Policy, error) {
			cfg, err := rt.parse(data)
			return cfg.Policy, err
		},
	})
	rt.watcher.Start()
}

// Close stops hot reload. The audit log stays owned by the caller of openAudit.
func (rt *policyRuntime) Close() {
	if rt == nil {
		return
	}
	if rt.watcher != nil {
		rt.watcher.Close()
	}
	rt.mu.Lock()
	rt.auditlog = nil
	rt.mu.Unlock()
}
