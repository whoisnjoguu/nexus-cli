package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/external"
)

var (
	initStrict bool
	initForce  bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold nexus.yaml and MCP host configs in the current project",
	RunE: func(cmd *cobra.Command, args []string) error {
		files := map[string]string{
			"nexus.yaml":       external.Policy,
			".claude/mcp.json": external.ClaudeMCP(initStrict),
			".vscode/mcp.json": external.VSCodeMCP(initStrict),
		}
		for path, content := range files {
			if err := writeScaffold(path, content, initForce); err != nil {
				return err
			}
		}
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Edit nexus.yaml to describe your agent's allowed tools and egress.")
		fmt.Println("  2. nexus-cli login --provider slack       # authenticate via the nexus-framework Gateway")
		fmt.Println("  3. nexus-cli dev                          # start the gated proxy")
		return nil
	},
}

func writeScaffold(path, content string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		fmt.Printf("skip  %s (exists; use --force to overwrite)\n", path)
		return nil
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("write %s\n", path)
	return nil
}

func init() {
	initCmd.Flags().BoolVar(&initStrict, "strict", false, "Scaffold MCP configs in strict (approve-every-call) mode")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite existing files")
	rootCmd.AddCommand(initCmd)
}
