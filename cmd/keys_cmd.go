package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

var (
	keysKey        string
	keysRotateYes  bool
	keysMigrateTo  string
	keysPruneOlder time.Duration
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage and publish the token-signing key",
	Long: `keys manages the Ed25519 key that signs dual-actor tokens.

The key backend is chosen by NEXUS_KEY_BACKEND=auto|keychain|file (default auto: an existing key
file is used as-is, otherwise the OS keychain, falling back to a 0600 file when no keychain is
available). See docs/keys.md for the threat model.`,
}

var keysJWKSCmd = &cobra.Command{
	Use:   "jwks",
	Short: "Print the public verification keys (current + retired) as a JWKS for downstream services",
	Long: `jwks emits the Ed25519 public keys as a JSON Web Key Set: the current key plus any retired keys
still accepted after a rotation. Downstream services can fetch this to verify nexus-issued
dual-actor tokens themselves (selecting the key by the token's "kid" header), rather than trusting
proxy-injected headers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, backend, err := resolveKeyTarget(keysKey)
		if err != nil {
			return err
		}
		signer, _, err := jwt.LoadOrCreateSignerWith(path, backend)
		if err != nil {
			return err
		}
		out, err := json.MarshalIndent(signer.JWKS(), "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	},
}

var keysShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the signing key id, backend, public key and location",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, backend, err := resolveKeyTarget(keysKey)
		if err != nil {
			return err
		}
		signer, used, err := jwt.LoadOrCreateSignerWith(path, backend)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "kid:         %s\n", signer.Kid())
		fmt.Fprintf(w, "backend:     %s\n", used)
		fmt.Fprintf(w, "public key:  %s (Ed25519, base64url)\n", base64.RawURLEncoding.EncodeToString(signer.PublicKey()))
		fmt.Fprintf(w, "location:    %s\n", signer.Location())
		fmt.Fprintf(w, "retired:     %d key(s) in %s\n", len(signer.RetiredKeys()), jwt.RetiredPath(path))
		return nil
	},
}

var keysRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace the signing key, keeping the old public key valid for verification",
	Long: `rotate generates a new signing key in the same backend and moves the old public key to the
retired list, so tokens minted before the rotation keep verifying until they expire. Running
proxies load keys at start-up and must be restarted; downstream JWKS consumers must refresh.
Prune old keys later with: nexus-cli keys prune --older-than 720h`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, backend, err := resolveKeyTarget(keysKey)
		if err != nil {
			return err
		}
		if !keysRotateYes {
			fmt.Fprint(cmd.OutOrStdout(), "Rotate the token-signing key? Running proxies must be restarted. [y/N] ")
			line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
				return fmt.Errorf("rotation aborted (pass --yes to skip the prompt)")
			}
		}
		res, err := jwt.Rotate(path, backend)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "rotated signing key (%s backend)\n", res.Backend)
		fmt.Fprintf(w, "old kid: %s (retired; still accepted until pruned)\n", res.OldKid)
		fmt.Fprintf(w, "new kid: %s\n", res.NewKid)
		fmt.Fprintln(w, "warning: restart running proxies and have downstream JWKS consumers refresh (nexus-cli keys jwks)")
		return nil
	},
}

var keysMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Move the signing key between the file and OS keychain backends",
	Long: `migrate copies the signing seed into the destination backend, verifies it reads back
identically, and only then deletes it from the source. When migrating to the keychain the key file
is overwritten before removal (best-effort on SSD/copy-on-write filesystems).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := resolveKeyPath(keysKey)
		if err != nil {
			return err
		}
		to, err := jwt.ParseBackend(keysMigrateTo)
		if err != nil || to == jwt.BackendAuto {
			return fmt.Errorf("--to must be keychain or file")
		}
		res, err := jwt.Migrate(path, to)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "migrated signing key %s from %s to %s\n", res.Kid, res.From, res.To)
		fmt.Fprintf(w, "location: %s\n", res.Signer.Location())
		if res.To == string(jwt.BackendKeychain) {
			fmt.Fprintf(w, "tip: set %s=keychain so a key file planted at %s is never used\n", jwt.KeyBackendEnv, path)
		}
		return nil
	},
}

var keysPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Drop retired keys older than a given age (their tokens stop verifying)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if keysPruneOlder < 0 {
			return fmt.Errorf("--older-than must not be negative")
		}
		path, backend, err := resolveKeyTarget(keysKey)
		if err != nil {
			return err
		}
		signer, _, err := jwt.LoadOrCreateSignerWith(path, backend)
		if err != nil {
			return err
		}
		n, err := signer.PruneRetired(keysPruneOlder)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "pruned %d retired key(s); %d remain\n", n, len(signer.RetiredKeys()))
		return nil
	},
}

func init() {
	keysCmd.PersistentFlags().StringVar(&keysKey, "key", "", "Path to the persistent Ed25519 key (default $NEXUS_HOME/ed25519.key or ~/.nexus/ed25519.key)")
	keysRotateCmd.Flags().BoolVarP(&keysRotateYes, "yes", "y", false, "Skip the confirmation prompt")
	keysMigrateCmd.Flags().StringVar(&keysMigrateTo, "to", "", "Destination backend: keychain or file")
	_ = keysMigrateCmd.MarkFlagRequired("to")
	keysPruneCmd.Flags().DurationVar(&keysPruneOlder, "older-than", 720*time.Hour, "Remove retired keys retired longer ago than this")
	keysCmd.AddCommand(keysJWKSCmd, keysShowCmd, keysRotateCmd, keysMigrateCmd, keysPruneCmd)
	rootCmd.AddCommand(keysCmd)
}
