// Package cmd wires the nexus-cli Cobra command tree.
package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nexus-cli",
	Short: "Nexus Security CLI - Zero-Trust Developer Proxy for Autonomous Agents",
	Long: `nexus-cli mitigates Tool Chain Exposure and Identity Fluidity by offering
ephemeral dual-actor token minting and interactive Human-in-the-Loop proxy controls.`,
	// main prints the error once; cobra would otherwise print it a second time.
	SilenceErrors: true,
	// Args and flags are valid by now, so a runtime failure shouldn't dump usage text.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		cmd.SilenceUsage = true
	},
}
`
func Execute() error {
	return rootCmd.Execute()
}

// Build metadata, populated by SetVersion from main's -ldflags values.
var (
	buildVersion = "dev"
	buildCommit  = ""
)

// SetVersion wires the build-time version/commit into the root command's --version output.
func SetVersion(version, commit string) {
	buildVersion, buildCommit = version, commit
	if commit != "" {
		rootCmd.Version = version + " (" + commit + ")"
	} else {
		rootCmd.Version = version
	}
}

func init() {
	rootCmd.AddCommand(devCmd)
	rootCmd.AddCommand(identityCmd)
}
