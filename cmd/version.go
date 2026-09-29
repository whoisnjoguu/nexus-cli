package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the nexus-cli version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("nexus-cli %s\n", buildVersion)
		if buildCommit != "" {
			fmt.Printf("commit:  %s\n", buildCommit)
		}
		fmt.Printf("go:      %s\n", runtime.Version())
		fmt.Printf("os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
