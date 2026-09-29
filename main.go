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
		fmt.Fprintf(os.Stderr, "Nexus CLI Execution Error: %v\n", err)
		os.Exit(1)
	}
}
