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
		peFile = resolvePolicyPath(cmd)
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
	return writePolicyBytes(path, append([]byte(header), data...))
}

// writePolicyBytes atomically replaces a policy file (a hot-reloading proxy never reads a
// half-written file; the file's mode is kept, 0600 for a new file). Writes come from a human
// (TUI edit, approval "always allow"), so a pinned file is re-pinned: the pin is updated first,
// so a watcher never sees the new content with the old pin, and restored if the write fails.
func writePolicyBytes(path string, data []byte) error {
	pinFile, err := policy.PinPath()
	if err != nil {
		return err
	}
	old, pinned, err := policy.ReadPin(pinFile, path)
	if err != nil {
		return fmt.Errorf("read policy pin: %w", err)
	}
	if pinned {
		if err := policy.WritePin(pinFile, path, policy.Sum(data)); err != nil {
			return fmt.Errorf("re-pin policy: %w", err)
		}
	}
	if err := atomicfile.Write(path, data, 0); err != nil {
		if pinned {
			_ = policy.WritePin(pinFile, path, old)
		}
		return err
	}
	return nil
}

func init() {
	policyEditCmd.Flags().StringVar(&peFile, "policy", "", policyFlagHelp)
	policyEditCmd.Flags().StringVar(&peGateway, "gateway", "", "Gateway URL for the provider catalog (or NEXUS_GATEWAY_URL / session)")
	policyCmd.AddCommand(policyEditCmd)
}
