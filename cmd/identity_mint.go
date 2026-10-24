package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

var (
	agentID string
	userID  string
	scopes  string
	ttlSec  int
	mintKey string
	mintOne bool
	mintQ   bool
)

var identityMintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Mint a short-lived dual-actor JWT for an agent session",
	Long: `Mint a short-lived dual-actor JWT binding an agent to the logged-in human.

Proxy tokens are reusable until they expire, so one token can serve every request an agent makes
through HTTP_PROXY=http://agent:<token>@127.0.0.1:8075. Pass --single-use to make the proxy reject
any reuse. Use -q to print only the token, e.g. TOKEN=$(nexus-cli identity mint -a my-agent -q).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if ttlSec <= 0 {
			return fmt.Errorf("--ttl must be greater than 0 seconds (got %d)", ttlSec)
		}
		path, err := resolveKeyPath(mintKey)
		if err != nil {
			return err
		}
		signer, err := jwt.LoadOrCreateSigner(path)
		if err != nil {
			return err
		}

		// bind act_as to the logged-in human principal
		actAs := userID
		var ceiling []string
		var connID, gateway string
		if p, perr := loadPrincipal(); perr == nil && p != nil && p.Valid() {
			actAs = p.Subject
			ceiling = p.Scopes
			connID = p.ConnectionID
			gateway = p.GatewayURL
		}
		if actAs == "" {
			return fmt.Errorf("no human principal: run 'nexus-cli login' or pass --user-id")
		}

		scopeList := strings.Split(scopes, ",")
		if len(ceiling) > 0 {
			requested := scopeList
			scopeList = (&principalCap{ceiling}).cap(scopeList)
			if len(scopeList) == 0 && strings.TrimSpace(scopes) != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: none of the requested scopes %v are within your login ceiling %v; token has no scopes\n", requested, ceiling)
			}
		}
		ttl := time.Duration(ttlSec) * time.Second

		tokenStr, err := signer.Mint(jwt.MintOptions{
			AgentID:   agentID,
			UserID:    actAs,
			Scopes:    scopeList,
			ConnID:    connID,
			Gateway:   gateway,
			TTL:       ttl,
			SingleUse: mintOne,
		})
		if err != nil {
			return fmt.Errorf("failed to mint dual-actor token: %w", err)
		}

		out := cmd.OutOrStdout()
		if mintQ {
			fmt.Fprintln(out, tokenStr)
			return nil
		}
		usage := "reusable until expiry"
		if mintOne {
			usage = "single-use"
		}
		fmt.Fprintln(out, "\n--- Minted Dual-Actor Identity Token ---")
		fmt.Fprintf(out, "Agent ID (sub):    %s\n", agentID)
		fmt.Fprintf(out, "Human User (act):  %s\n", actAs)
		fmt.Fprintf(out, "Scopes:            %s\n", strings.Join(scopeList, ","))
		if connID != "" {
			fmt.Fprintf(out, "Broker Conn:       %s\n", connID)
		}
		fmt.Fprintf(out, "Lifespan (TTL):    %ds (%s)\n", ttlSec, usage)
		fmt.Fprintf(out, "Signing Key:       %s\n", path)
		fmt.Fprintf(out, "Micro-JWT:         %s\n", tokenStr)
		return nil
	},
}

// principalCap intersects requested scopes with a ceiling
type principalCap struct{ ceiling []string }

func (c *principalCap) cap(requested []string) []string {
	allow := make(map[string]bool, len(c.ceiling))
	for _, s := range c.ceiling {
		allow[s] = true
	}
	var out []string
	for _, s := range requested {
		if allow[s] {
			out = append(out, s)
		}
	}
	return out
}

func init() {
	identityMintCmd.Flags().StringVarP(&agentID, "agent-id", "a", "", "Unique Agent ID (Required)")
	identityMintCmd.Flags().StringVarP(&userID, "user-id", "u", "", "Human principal fallback when not logged in")
	identityMintCmd.Flags().StringVarP(&scopes, "scopes", "s", "read", "Comma-separated allowed scopes")
	identityMintCmd.Flags().IntVarP(&ttlSec, "ttl", "t", 900, "Token validity in seconds (proxy tokens are reusable until expiry unless --single-use)")
	identityMintCmd.Flags().BoolVar(&mintOne, "single-use", false, "Mark the token single-use: the proxy rejects any second request with it")
	identityMintCmd.Flags().BoolVarP(&mintQ, "quiet", "q", false, "Print only the token")
	identityMintCmd.Flags().StringVar(&mintKey, "key", "", "Path to the persistent Ed25519 key (default ~/.nexus/ed25519.key)")

	_ = identityMintCmd.MarkFlagRequired("agent-id")
}
