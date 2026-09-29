package cmd

import (
	"github.com/spf13/cobra"
)

var identityCmd = &cobra.Command{
	Use:   "identity",
	Short: "Mint and manage cryptographically verifiable dual-actor agent identities",
}

func init() {
	identityCmd.AddCommand(identityMintCmd)
}
