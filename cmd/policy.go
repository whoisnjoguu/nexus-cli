package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

var (
	ptMethod   string
	ptURL      string
	ptTool     string
	ptProvider string
	ptScopes   string
	ptFile     string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Inspect and dry-run the least-privilege policy",
}

var policyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Evaluate a hypothetical tool call against the policy without executing it",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, exists, err := loadConfig(ptFile)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("no policy file at %s (run 'nexus-cli init')", ptFile)
		}
		engine := policy.NewEngine(cfg.Policy)

		var host, path string
		if ptURL != "" {
			u, perr := url.Parse(ptURL)
			if perr != nil {
				return fmt.Errorf("parse --url: %w", perr)
			}
			host, path = u.Host, u.Path
		}
		var scopes []string
		if ptScopes != "" {
			scopes = strings.Split(ptScopes, ",")
		}

		dec := engine.Evaluate(policy.Request{
			SessionID: "policy-test",
			Method:    strings.ToUpper(ptMethod),
			Host:      host,
			Path:      path,
			Tool:      ptTool,
			Provider:  ptProvider,
			Scopes:    scopes,
		})
		fmt.Printf("Decision: %s\nReason:   %s\n", strings.ToUpper(string(dec.Action)), dec.Reason)
		return nil
	},
}

func init() {
	policyTestCmd.Flags().StringVar(&ptMethod, "method", "GET", "HTTP method")
	policyTestCmd.Flags().StringVar(&ptURL, "url", "", "Target URL (host + path are matched)")
	policyTestCmd.Flags().StringVar(&ptTool, "tool", "", "MCP tool name (for tool-match rules)")
	policyTestCmd.Flags().StringVar(&ptProvider, "provider", "", "Provider name (for request_access/get_credential rules)")
	policyTestCmd.Flags().StringVar(&ptScopes, "scopes", "", "Comma-separated scopes carried by the token")
	policyTestCmd.Flags().StringVar(&ptFile, "policy", "nexus.yaml", "Path to the policy file")

	policyCmd.AddCommand(policyTestCmd)
	rootCmd.AddCommand(policyCmd)
}
