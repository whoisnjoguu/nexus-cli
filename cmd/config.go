package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

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

// loadConfig reads nexus.yaml strictly: unknown keys anywhere (including the mcp: and audit:
// sections) and policy validation errors are rejected; warnings are not.
func loadConfig(path string) (cfg configFile, exists bool, err error) {
	data, rerr := os.ReadFile(path)
	if os.IsNotExist(rerr) {
		return configFile{}, false, nil
	}
	if rerr != nil {
		return configFile{}, false, fmt.Errorf("read config %s: %w", path, rerr)
	}
	cfg, err = parseConfig(path, data)
	if err != nil {
		return configFile{}, false, err
	}
	return cfg, true, nil
}

// parseConfig decodes and validates config bytes (see loadConfig).
func parseConfig(path string, data []byte) (configFile, error) {
	cfg, err := decodeConfig(path, data)
	if err != nil {
		return configFile{}, err
	}
	if verr := policy.Check(cfg.Policy); verr != nil {
		return configFile{}, fmt.Errorf("%s: %w", path, verr)
	}
	return cfg, nil
}

// configParseError is a YAML syntax or unknown-field error, split into per-line issues.
type configParseError struct {
	path   string
	issues []policy.Issue
}

func (e *configParseError) Error() string {
	msgs := make([]string, len(e.issues))
	for i, is := range e.issues {
		msgs[i] = strings.TrimPrefix(is.String(), "error ")
	}
	return fmt.Sprintf("parse config %s: %s", e.path, strings.Join(msgs, "; "))
}

// decodeConfig parses config bytes with unknown keys rejected, without policy validation.
func decodeConfig(path string, data []byte) (configFile, error) {
	var cfg configFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return configFile{}, &configParseError{path: path, issues: yamlIssues(err)}
	}
	return cfg, nil
}

var (
	yamlLineRe    = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)
	yamlUnknownRe = regexp.MustCompile(`^field (\S+) not found in type (.+)$`)
)

// yamlSections names the Go types behind each config section for unknown-field messages.
var yamlSections = map[string]string{
	"cmd.configFile":      "the top level",
	"policy.Match":        "a rule match",
	"policy.Rule":         "a tools rule",
	"policy.Egress":       "egress",
	"policy.ProviderRule": "a providers entry",
	"audit.Config":        "audit",
	"audit.SinkConfig":    "an audit.sinks entry",
	"mcp.UpstreamSpec":    "an mcp.upstreams entry",
}

// yamlIssues turns a yaml.v3 error into one issue per line, e.g. `line 4: unknown field "alow"
// in a rule match`.
func yamlIssues(err error) []policy.Issue {
	var lines []string
	var te *yaml.TypeError
	if errors.As(err, &te) {
		lines = te.Errors
	} else {
		lines = []string{err.Error()}
	}
	issues := make([]policy.Issue, 0, len(lines))
	for _, l := range lines {
		is := policy.Issue{Severity: policy.SeverityError, Msg: strings.TrimPrefix(l, "yaml: ")}
		if m := yamlLineRe.FindStringSubmatch(l); m != nil {
			is.Path, is.Msg = "line "+m[1], m[2]
		}
		if m := yamlUnknownRe.FindStringSubmatch(is.Msg); m != nil {
			section, ok := yamlSections[m[2]]
			if !ok {
				section = "mcp"
				if !strings.HasPrefix(m[2], "struct") {
					section = m[2]
				}
			}
			is.Msg = fmt.Sprintf("unknown field %q in %s", m[1], section)
		}
		issues = append(issues, is)
	}
	return issues
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
