package cmd

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/mcp"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// configFile is the on-disk nexus.yaml
type configFile struct {
	policy.Policy `yaml:",inline"`
	MCP           struct {
		Upstreams []mcp.UpstreamSpec `yaml:"upstreams"`
	} `yaml:"mcp"`
	Audit audit.Config `yaml:"audit,omitempty"`
}

// loadConfig reads nexus.yaml
func loadConfig(path string) (cfg configFile, exists bool, err error) {
	data, rerr := os.ReadFile(path)
	if os.IsNotExist(rerr) {
		return configFile{}, false, nil
	}
	if rerr != nil {
		return configFile{}, false, fmt.Errorf("read config %s: %w", path, rerr)
	}
	if uerr := yaml.Unmarshal(data, &cfg); uerr != nil {
		return configFile{}, false, fmt.Errorf("parse config %s: %w", path, uerr)
	}
	return cfg, true, nil
}

// appendPolicyRule adds an "always allow" rule to the policy file
func appendPolicyRule(path string, rule policy.Rule) error {
	cfg, exists, err := loadConfig(path)
	if err != nil {
		return err
	}
	if !exists {
		cfg.Policy = policy.DefaultPolicy()
	}
	// Prepend so the new allow wins over a broader hitl/deny below it.
	cfg.Policy.Tools = append([]policy.Rule{rule}, cfg.Policy.Tools...)
	return writeConfig(path, cfg)
}

// openAuditLog opens the audit log configured by the `audit:` section of the policy file at
// policyPath (signing, rotation, fsync, off-box sinks), falling back to defaults when the file or
// section is absent. It returns the logger and the active log path.
func openAuditLog(policyPath string) (*audit.Logger, string, error) {
	cfg, _, err := loadConfig(policyPath)
	if err != nil {
		return nil, "", err
	}
	path, err := cfg.Audit.ResolvedPath()
	if err != nil {
		return nil, "", err
	}
	l, err := cfg.Audit.Open()
	if err != nil {
		return nil, "", fmt.Errorf("open audit log: %w", err)
	}
	return l, path, nil
}
