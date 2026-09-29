package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/whoisnjoguu/nexus-cli/internal/tui"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

var (
	peFile    string
	peGateway string
)

var policyEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Interactively edit the policy (providers, tools, egress, defaults) and write nexus.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, err := loadConfig(peFile)
		if err != nil {
			return err
		}

		p, _ := loadPrincipal()
		gateway := resolveGateway(peGateway, p)
		var providers []principal.ProviderInfo
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if list, lerr := principal.ListProviders(ctx, gateway); lerr == nil {
			providers = list
		} else {
			fmt.Fprintf(os.Stderr, "note: could not load providers from %s (%v); editing without the catalog\n", gateway, lerr)
		}
		cancel()

		edited, saved, err := tui.Run(tui.Options{Policy: cfg.Policy, Providers: providers})
		if err != nil {
			return err
		}
		if !saved {
			fmt.Println("No changes saved.")
			return nil
		}

		cfg.Policy = edited
		if err := writeConfig(peFile, cfg); err != nil {
			return err
		}
		fmt.Printf("✔ Saved %s\n", peFile)
		return nil
	},
}

// writeConfig serializes the policy + mcp upstreams back to the config file.
func writeConfig(path string, cfg configFile) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	header := "# Managed by `nexus-cli policy edit`. Hand edits are preserved on next open,\n# but inline comments are not.\n"
	if err := os.WriteFile(path, append([]byte(header), data...), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func init() {
	policyEditCmd.Flags().StringVar(&peFile, "policy", "nexus.yaml", "Path to the policy file")
	policyEditCmd.Flags().StringVar(&peGateway, "gateway", "", "Gateway URL for the provider catalog (or NEXUS_GATEWAY_URL / session)")
	policyCmd.AddCommand(policyEditCmd)
}
