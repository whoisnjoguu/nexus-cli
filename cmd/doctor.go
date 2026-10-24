package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	oauthsdk "github.com/Prescott-Data/nexus-framework/nexus-sdk"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

var doctorPolicy string

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose the local nexus-cli setup (key, login, policy, audit chain)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ok := true

		keyPath, err := jwt.DefaultKeyPath()
		if err == nil {
			backend, berr := jwt.BackendFromEnv()
			if berr != nil {
				ok = false
				check(false, berr.Error())
			}
			inFile := false
			if _, serr := os.Stat(keyPath); serr == nil {
				inFile = true
			}
			inKeychain := false
			if backend != jwt.BackendFile {
				if ks, kerr := jwt.NewKeychainKeyStore(keyPath); kerr == nil {
					if _, lerr := ks.Load(); lerr == nil {
						inKeychain = true
					}
				}
			}
			switch {
			case inFile && inKeychain:
				ok = false
				check(false, "signing key exists both as "+keyPath+" and in the OS keychain — remove the one you did not create")
			case inKeychain:
				check(true, "signing key present in the OS keychain (for "+keyPath+")")
			case inFile:
				check(true, "signing key present at "+keyPath)
			default:
				check(true, "signing key will be created on first use ("+keyPath+")")
			}
		}

		p, perr := loadPrincipal()
		switch {
		case perr != nil:
			ok = false
			check(false, "session unreadable: "+perr.Error())
		case p == nil || !p.Valid():
			check(false, "not logged in (run: nexus-cli login) — act_as will be 'unknown-user'")
		default:
			check(true, fmt.Sprintf("logged in as %s (issuer: %s)", p.Subject, p.Issuer))
		}

		// if the principal is broker-backed, confirm the connection is still active.
		if p != nil && p.ConnectionID != "" && p.GatewayURL != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			client := oauthsdk.New(p.GatewayURL)
			status, cerr := client.CheckConnection(ctx, p.ConnectionID)
			cancel()
			if cerr != nil {
				ok = false
				check(false, "gateway unreachable at "+p.GatewayURL+": "+cerr.Error())
			} else if status != "active" {
				ok = false
				check(false, "broker connection not active (status: "+status+") — re-run login")
			} else {
				check(true, "broker connection active at "+p.GatewayURL)
			}
		}

		if _, exists, cerr := loadConfig(doctorPolicy); cerr != nil {
			ok = false
			check(false, "policy invalid: "+cerr.Error())
		} else if exists {
			check(true, "policy loaded from "+doctorPolicy)
		} else {
			check(false, "no policy file at "+doctorPolicy+" (run: nexus-cli init) — proxy uses method heuristics")
		}

		if apath, aerr := auditLogPath(); aerr == nil {
			opts, _, oerr := auditVerifyOptions()
			if oerr != nil {
				ok = false
				check(false, "audit public key unreadable: "+oerr.Error())
			}
			if res, verr := audit.VerifyWithOptions(apath, opts); verr != nil {
				ok = false
				check(false, "audit chain INVALID: "+verr.Error())
			} else {
				msg := fmt.Sprintf("audit chain intact (%d entries", res.Entries)
				if res.SigsChecked {
					msg += fmt.Sprintf(", %d signatures verified", res.Signed)
				} else if res.Signed > 0 {
					msg += fmt.Sprintf(", %d signed but no audit.pub to check them", res.Signed)
				}
				check(true, msg+")")
			}
		}

		if !ok {
			return fmt.Errorf("doctor found issues")
		}
		return nil
	},
}

func check(pass bool, msg string) {
	mark := "✔"
	if !pass {
		mark = "✖"
	}
	fmt.Printf("%s %s\n", mark, msg)
}

func init() {
	doctorCmd.Flags().StringVar(&doctorPolicy, "policy", "nexus.yaml", "Path to the policy file")
	rootCmd.AddCommand(doctorCmd)
}
