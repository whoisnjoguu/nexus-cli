package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/mcp"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

var (
	mcpStrict  bool
	mcpKey     string
	mcpPolicy  string
	mcpAgentID string
	mcpGateway string
	mcpNoAudit bool
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Model Context Protocol gateway commands",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve nexus-cli as an MCP stdio server / gateway for agent hosts (Claude Code, etc.)",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveKeyPath(mcpKey)
		if err != nil {
			return err
		}
		signer, err := jwt.LoadOrCreateSigner(path)
		if err != nil {
			return err
		}

		mcfg := mcp.Config{Signer: signer, Strict: mcpStrict, AgentID: mcpAgentID}

		if cfg, exists, cerr := loadConfig(mcpPolicy); cerr != nil {
			return cerr
		} else if exists {
			mcfg.Engine = policy.NewEngine(cfg.Policy)
			mcfg.Upstreams = cfg.MCP.Upstreams
		} else {
			mcfg.Engine = policy.NewEngine(policy.DefaultPolicy())
		}
		mcfg.OnPersistRule = func(rule policy.Rule) {
			if err := appendPolicyRule(mcpPolicy, rule); err != nil {
				fmt.Fprintf(os.Stderr, "note: could not persist rule to %s: %v\n", mcpPolicy, err)
			}
		}

		// Bind act_as to the logged-in human so the agent cannot forge it, and expose the human's
		// existing broker connections to the request_access / credential tools.
		gateway := mcpGateway
		if gateway == "" {
			gateway = os.Getenv("NEXUS_GATEWAY_URL")
		}
		if p, perr := loadPrincipal(); perr == nil && p != nil && p.Valid() {
			mcfg.ActAs = p.Subject
			mcfg.Ceiling = p.Scopes
			mcfg.Session = p
			if gateway == "" {
				gateway = p.GatewayURL
			}
		}
		mcfg.Gateway = gateway
		if sp, serr := principal.DefaultSessionPath(); serr == nil {
			mcfg.SessionPath = sp
		}

		if !mcpNoAudit {
			apath, aerr := audit.DefaultPath()
			if aerr != nil {
				return aerr
			}
			mcfg.Audit, aerr = audit.Open(apath)
			if aerr != nil {
				return aerr
			}
		}

		server, err := mcp.New(mcfg)
		if err != nil {
			return fmt.Errorf("start mcp gateway: %w", err)
		}
		defer server.Close()
		return server.Serve()
	},
}

func init() {
	mcpServeCmd.Flags().BoolVar(&mcpStrict, "strict", false, "Require HITL approval for every tool call")
	mcpServeCmd.Flags().StringVar(&mcpKey, "key", "", "Path to the persistent Ed25519 key (default ~/.nexus/ed25519.key)")
	mcpServeCmd.Flags().StringVar(&mcpPolicy, "policy", "nexus.yaml", "Path to the policy/gateway config file")
	mcpServeCmd.Flags().StringVar(&mcpAgentID, "agent-id", "mcp-agent", "Agent identity to attribute tool calls to")
	mcpServeCmd.Flags().StringVar(&mcpGateway, "gateway", "", "nexus-framework Gateway URL for broker-access tools (or NEXUS_GATEWAY_URL / session)")
	mcpServeCmd.Flags().BoolVar(&mcpNoAudit, "no-audit", false, "Disable the tamper-evident audit log")

	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}
