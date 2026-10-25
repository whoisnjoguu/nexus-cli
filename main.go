package main

import (
	"fmt"
	"os"

	"github.com/whoisnjoguu/nexus-cli/cmd"
)

// Populated at build time via -ldflags (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = ""
)

func main() {
	cmd.SetVersion(version, commit)
	if err := cmd.Execute(); err != nil {
		// `nexus-cli run` propagates its child's exit status without an extra error line.
		if code, ok := cmd.ExitCode(err); ok {
			os.Exit(code)
		}
		fmt.Fprintf(os.Stderr, "Nexus CLI Execution Error: %v\n", err)
		os.Exit(1)
	}
}
