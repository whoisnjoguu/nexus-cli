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
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
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

		doctorPolicy = resolvePolicyPath(cmd)
		if _, serr := os.Stat(doctorPolicy); serr != nil {
			check(false, "no policy file at "+doctorPolicy+" (run: nexus-cli init) — the safe-tier default policy applies")
		} else if issues, lerr := lintPolicyFile(doctorPolicy); lerr != nil {
			ok = false
			check(false, "policy unreadable: "+lerr.Error())
		} else {
			errs, warns := policy.CountIssues(issues)
			if errs > 0 {
				ok = false
				check(false, fmt.Sprintf("policy %s has %d error(s), %d warning(s) — run: nexus-cli policy lint", doctorPolicy, errs, warns))
			} else {
				msg := fmt.Sprintf("policy loaded from %s (0 errors, %d warning(s)", doctorPolicy, warns)
				if warns > 0 {
					msg += " — run: nexus-cli policy lint"
				}
				check(true, msg+")")
			}
			pinFile, _ := policy.PinPath()
			if data, rerr := os.ReadFile(doctorPolicy); rerr == nil && pinFile != "" {
				switch pinned, perr := policy.CheckPin(pinFile, doctorPolicy, data); {
				case perr != nil:
					ok = false
					check(false, perr.Error())
				case pinned:
					check(true, "policy matches its pin ("+pinFile+")")
				default:
					check(true, "policy not pinned (optional: nexus-cli policy pin)")
				}
			}
			if insideWorkspace(doctorPolicy) {
				check(false, "policy "+displayPath(doctorPolicy)+" is inside the current directory (an agent's workspace could edit it) — consider: nexus-cli policy protect")
			}
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
	doctorCmd.Flags().StringVar(&doctorPolicy, "policy", "nexus.yaml", policyFlagHelp)
	rootCmd.AddCommand(doctorCmd)
}
