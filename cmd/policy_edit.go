package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/whoisnjoguu/nexus-cli/internal/atomicfile"
	"github.com/whoisnjoguu/nexus-cli/internal/tui"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
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

		if verr := policy.Check(edited); verr != nil {
			return fmt.Errorf("not saved: %w", verr)
		}
		cfg.Policy = edited
		if err := writeConfig(peFile, cfg); err != nil {
			return err
		}
		fmt.Printf("✔ Saved %s\n", peFile)
		return nil
	},
}

// writeConfig serializes the whole config (policy, mcp: and audit: sections) back to the file.
func writeConfig(path string, cfg configFile) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	header := "# Managed by `nexus-cli policy edit`. Hand edits are preserved on next open,\n# but inline comments are not.\n"
	// Atomic replace: a hot-reloading proxy never reads a half-written file. Keeps the file's
	// mode (0600 for a new file).
	return atomicfile.Write(path, append([]byte(header), data...), 0)
}

func init() {
	policyEditCmd.Flags().StringVar(&peFile, "policy", "nexus.yaml", "Path to the policy file")
	policyEditCmd.Flags().StringVar(&peGateway, "gateway", "", "Gateway URL for the provider catalog (or NEXUS_GATEWAY_URL / session)")
	policyCmd.AddCommand(policyEditCmd)
}
