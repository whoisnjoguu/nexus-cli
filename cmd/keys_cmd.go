package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

var keysKey string

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage and publish the token-signing key",
}

var keysJWKSCmd = &cobra.Command{
	Use:   "jwks",
	Short: "Print the public verification key as a JWKS for downstream services",
	Long: `jwks emits the Ed25519 public key as a JSON Web Key Set. Downstream services can fetch this
to verify nexus-issued dual-actor tokens themselves, rather than trusting proxy-injected headers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveKeyPath(keysKey)
		if err != nil {
			return err
		}
		signer, err := jwt.LoadOrCreateSigner(path)
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(signer.JWKS(), "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	keysCmd.PersistentFlags().StringVar(&keysKey, "key", "", "Path to the persistent Ed25519 key (default ~/.nexus/ed25519.key)")
	keysCmd.AddCommand(keysJWKSCmd)
	rootCmd.AddCommand(keysCmd)
}
