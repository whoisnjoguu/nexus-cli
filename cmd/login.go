package cmd

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

var (
	loginProvider       string
	loginGateway        string
	loginUserID         string
	loginProviderScopes string
	loginReturnURL      string
	loginEmail          string
	loginSubject        string
	loginScopes         string
	loginTTLHours       int
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate the human principal (act_as) that agents operate on behalf of",
	Long: `login establishes the verified human identity an agent acts for. The identity comes from
a provider the agent cannot forge and caps the scopes the agent may later request.

Authentication is brokered by the nexus-framework Gateway — nexus-cli holds no OAuth code and
never sees a raw secret. Any provider registered with the Gateway works by name.

  --provider slack       Broker consent via the Gateway (github, slack, google, your IdP, ...)
  --provider local       Offline identity from --email/--subject (no Gateway, weak attribution)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var ceiling []string
		if loginScopes != "" {
			ceiling = strings.Split(loginScopes, ",")
		}
		var providerScopes []string
		if loginProviderScopes != "" {
			providerScopes = strings.Split(loginProviderScopes, ",")
		}
		ttl := time.Duration(loginTTLHours) * time.Hour

		var provider principal.Provider
		switch loginProvider {
		case "local":
			provider = principal.LocalProvider{Subject: loginSubject, Email: loginEmail, Scopes: ceiling, TTL: ttl}
		default:
			// Every non-local provider name is delegated to the nexus-framework Gateway.
			gateway := loginGateway
			if gateway == "" {
				gateway = os.Getenv("NEXUS_GATEWAY_URL")
			}
			provider = principal.NexusProvider{
				GatewayURL:     gateway,
				ProviderName:   loginProvider,
				UserID:         defaultUserID(loginUserID),
				ProviderScopes: providerScopes,
				Ceiling:        ceiling,
				ReturnURL:      loginReturnURL,
				TTL:            ttl,
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		p, err := provider.Login(ctx)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}

		path, err := principal.DefaultSessionPath()
		if err != nil {
			return err
		}
		if err := principal.Save(path, p); err != nil {
			return err
		}
		fmt.Printf("\n✔ Logged in as %s (issuer: %s)\n", p.Subject, p.Issuer)
		if p.ConnectionID != "" {
			fmt.Printf("  Broker connection: %s @ %s\n", p.ConnectionID, p.GatewayURL)
		}
		if len(p.Scopes) > 0 {
			fmt.Printf("  Delegatable scope ceiling: %s\n", strings.Join(p.Scopes, ", "))
		}
		fmt.Printf("  Session cached at %s\n", path)
		return nil
	},
}

// defaultUserID falls back to the OS user when none is supplied, so the Gateway has a stable
// key to associate the connection with.
func defaultUserID(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		host, _ := os.Hostname()
		if host != "" {
			return u.Username + "@" + host
		}
		return u.Username
	}
	return "nexus-cli-user"
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Clear the cached human principal session",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := principal.DefaultSessionPath()
		if err != nil {
			return err
		}
		if err := principal.Clear(path); err != nil {
			return err
		}
		fmt.Println("✔ Logged out; session cleared")
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the currently logged-in human principal",
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := loadPrincipal()
		if err != nil {
			return err
		}
		if p == nil || !p.Valid() {
			fmt.Println("Not logged in (run: nexus-cli login). act_as will fall back to 'unknown-user'.")
			return nil
		}
		fmt.Printf("Subject: %s\nIssuer:  %s\n", p.Subject, p.Issuer)
		if p.Email != "" {
			fmt.Printf("Email:   %s\n", p.Email)
		}
		if p.ConnectionID != "" {
			fmt.Printf("Broker:  %s @ %s\n", p.ConnectionID, p.GatewayURL)
		}
		if len(p.Scopes) > 0 {
			fmt.Printf("Ceiling: %s\n", strings.Join(p.Scopes, ", "))
		}
		if !p.ExpiresAt.IsZero() {
			fmt.Printf("Expires: %s\n", p.ExpiresAt.Format(time.RFC3339))
		}
		return nil
	},
}

// loadPrincipal returns the cached human principal, or nil if none is present.
func loadPrincipal() (*principal.Principal, error) {
	path, err := principal.DefaultSessionPath()
	if err != nil {
		return nil, err
	}
	return principal.Load(path)
}

func init() {
	loginCmd.Flags().StringVar(&loginProvider, "provider", "", "Provider to authenticate with via the Gateway (github, slack, google, ...), or 'local'")
	loginCmd.Flags().StringVar(&loginGateway, "gateway", "", "nexus-framework Gateway URL (default "+principal.DefaultGatewayURL+", or NEXUS_GATEWAY_URL)")
	loginCmd.Flags().StringVar(&loginUserID, "user-id", "", "User ID the Gateway associates the connection with (default: OS user)")
	loginCmd.Flags().StringVar(&loginProviderScopes, "provider-scopes", "", "Comma-separated OAuth scopes to request from the provider")
	loginCmd.Flags().StringVar(&loginReturnURL, "return-url", "", "Post-consent redirect URL (default: a local loopback landing page)")
	loginCmd.Flags().StringVar(&loginEmail, "email", "", "Human email (local provider)")
	loginCmd.Flags().StringVar(&loginSubject, "subject", "", "Human subject/ID (local provider; defaults to email)")
	loginCmd.Flags().StringVar(&loginScopes, "scopes", "", "Comma-separated nexus scope ceiling this human may delegate")
	loginCmd.Flags().IntVar(&loginTTLHours, "ttl-hours", 8, "How long the login session is trusted")

	_ = loginCmd.MarkFlagRequired("provider")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
}
