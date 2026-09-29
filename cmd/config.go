package cmd

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/whoisnjoguu/nexus-cli/pkg/mcp"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// configFile is the on-disk nexus.yaml
type configFile struct {
	policy.Policy `yaml:",inline"`
	MCP           struct {
		Upstreams []mcp.UpstreamSpec `yaml:"upstreams"`
	} `yaml:"mcp"`
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
