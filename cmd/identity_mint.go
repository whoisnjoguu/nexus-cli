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
)

var identityMintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Mint a short-lived dual-actor JWT for an agent session",
	RunE: func(cmd *cobra.Command, args []string) error {
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
			scopeList = (&principalCap{ceiling}).cap(scopeList)
		}
		ttl := time.Duration(ttlSec) * time.Second

		tokenStr, err := signer.Mint(jwt.MintOptions{
			AgentID: agentID,
			UserID:  actAs,
			Scopes:  scopeList,
			ConnID:  connID,
			Gateway: gateway,
			TTL:     ttl,
		})
		if err != nil {
			return fmt.Errorf("failed to mint dual-actor token: %w", err)
		}

		fmt.Println("\n--- Minted Dual-Actor Identity Token ---")
		fmt.Printf("Agent ID (sub):    %s\n", agentID)
		fmt.Printf("Human User (act):  %s\n", actAs)
		fmt.Printf("Scopes:            %s\n", strings.Join(scopeList, ","))
		if connID != "" {
			fmt.Printf("Broker Conn:       %s\n", connID)
		}
		fmt.Printf("Lifespan (TTL):    %ds\n", ttlSec)
		fmt.Printf("Signing Key:       %s\n", path)
		fmt.Printf("Micro-JWT:         %s\n", tokenStr)
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
	identityMintCmd.Flags().IntVarP(&ttlSec, "ttl", "t", 30, "Token validity in seconds")
	identityMintCmd.Flags().StringVar(&mintKey, "key", "", "Path to the persistent Ed25519 key (default ~/.nexus/ed25519.key)")

	_ = identityMintCmd.MarkFlagRequired("agent-id")
}
