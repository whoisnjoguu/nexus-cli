package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
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

	watcher *policy.Watcher
}

// loadPolicyRuntime loads the policy at path strictly (or the safe-tier default when absent) and
// builds its engine. It reads the file once, so the hash, the policy and the config agree.
func loadPolicyRuntime(path string) (*policyRuntime, error) {
	rt := &policyRuntime{Path: path}
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
	return rt, nil
}

// parse is the strict loader shared by startup and hot reload.
func (rt *policyRuntime) parse(data []byte) (configFile, error) {
	return parseConfig(rt.Path, data)
}

// openAudit opens the audit log configured by the loaded file's audit: section.
func (rt *policyRuntime) openAudit() (*audit.Logger, string, error) {
	return openAuditConfig(rt.Config)
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
		Load: func(data []byte) (policy.Policy, error) {
			cfg, err := rt.parse(data)
			return cfg.Policy, err
		},
	})
	rt.watcher.Start()
}

// Close stops hot reload.
func (rt *policyRuntime) Close() {
	if rt != nil && rt.watcher != nil {
		rt.watcher.Close()
	}
}
