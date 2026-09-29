package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

var (
	connectProvider string
	connectScopes   string
	connectGateway  string
)

// resolveGateway picks the gateway from the flag, env, or the logged-in session.
func resolveGateway(flag string, p *principal.Principal) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("NEXUS_GATEWAY_URL"); env != "" {
		return env
	}
	if p != nil && p.GatewayURL != "" {
		return p.GatewayURL
	}
	return principal.DefaultGatewayURL
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect an additional provider (broker connection) to your session",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := loadPrincipal()
		if err != nil {
			return err
		}
		if p == nil || !p.Valid() {
			return fmt.Errorf("not logged in: run 'nexus-cli login' first")
		}
		var scopes []string
		if connectScopes != "" {
			scopes = strings.Split(connectScopes, ",")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		res, err := principal.Connect(ctx, principal.ConnectOptions{
			GatewayURL:     resolveGateway(connectGateway, p),
			ProviderName:   connectProvider,
			UserID:         p.Subject,
			ProviderScopes: scopes,
		})
		if err != nil {
			return fmt.Errorf("connect failed: %w", err)
		}
		conn := res.Connection()
		conn.Status = "active"
		p.AddConnection(conn)

		path, err := principal.DefaultSessionPath()
		if err != nil {
			return err
		}
		if err := principal.Save(path, p); err != nil {
			return err
		}
		fmt.Printf("\n✔ Connected %s (connection %s)\n", res.Provider, res.ConnectionID)
		return nil
	},
}

var connectionsCmd = &cobra.Command{
	Use:   "connections",
	Short: "List the provider connections in your session",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := loadPrincipal()
		if err != nil {
			return err
		}
		if p == nil || len(p.Connections) == 0 {
			fmt.Println("No provider connections. Use 'nexus-cli connect --provider <name>'.")
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, name := range p.Providers() {
			c := p.Connections[name]
			status := c.Status
			if st, serr := principal.CheckStatus(ctx, c.GatewayURL, c.ConnectionID); serr == nil {
				status = st
			}
			state := "pending"
			if principal.IsActiveStatus(status) {
				state = "active"
			}
			fmt.Printf("%-16s %-8s %s\n", name, state, c.ConnectionID)
		}
		return nil
	},
}

var providersCmd = &cobra.Command{
	Use:   "providers",
	Short: "List providers available on the nexus-framework Gateway",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, _ := loadPrincipal()
		gateway := resolveGateway(connectGateway, p)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		providers, err := principal.ListProviders(ctx, gateway)
		if err != nil {
			return fmt.Errorf("list providers: %w", err)
		}
		fmt.Printf("Providers on %s (%d):\n", gateway, len(providers))
		for _, pr := range providers {
			fmt.Printf("  %-20s %-8s %s\n", pr.Name, pr.AuthType, pr.Category)
		}
		return nil
	},
}

func init() {
	connectCmd.Flags().StringVar(&connectProvider, "provider", "", "Provider to connect (e.g. github, google-drive)")
	connectCmd.Flags().StringVar(&connectScopes, "scopes", "", "Comma-separated OAuth scopes (defaults to the Gateway's registered set)")
	connectCmd.Flags().StringVar(&connectGateway, "gateway", "", "Gateway URL (or NEXUS_GATEWAY_URL / session)")
	_ = connectCmd.MarkFlagRequired("provider")

	providersCmd.Flags().StringVar(&connectGateway, "gateway", "", "Gateway URL (or NEXUS_GATEWAY_URL / session)")

	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(connectionsCmd)
	rootCmd.AddCommand(providersCmd)
}
