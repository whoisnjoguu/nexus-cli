package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/credential"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/proxy"
)

var (
	proxyPort   int
	strictMode  bool
	requireAuth bool
	devKeyPath  string
	devPolicy   string
	devNoAudit  bool
	devInject   bool
)

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Start local zero-trust proxy with policy enforcement and Human-in-the-Loop approval",
	RunE: func(cmd *cobra.Command, args []string) error {
		var verifier *jwt.Verifier
		var replay *jwt.ReplayGuard
		if requireAuth {
			path, err := resolveKeyPath(devKeyPath)
			if err != nil {
				return err
			}
			signer, err := jwt.LoadOrCreateSigner(path)
			if err != nil {
				return err
			}
			verifier = signer.Verifier()
			replay = jwt.NewReplayGuard()
		}

		var engine *policy.Engine
		if cfg, exists, err := loadConfig(devPolicy); err != nil {
			return err
		} else if exists {
			engine = policy.NewEngine(cfg.Policy)
			fmt.Printf("📜 policy loaded from %s (agent: %s)\n", devPolicy, cfg.Agent)
		} else {
			engine = policy.NewEngine(policy.DefaultPolicy())
			fmt.Printf("📜 no %s found — using the safe-tier default policy (reads allowed, writes ask, shell denied)\n", devPolicy)
		}

		var auditlog *audit.Logger
		if !devNoAudit {
			apath, err := audit.DefaultPath()
			if err != nil {
				return err
			}
			auditlog, err = audit.Open(apath)
			if err != nil {
				return err
			}
			fmt.Printf("📓 audit log: %s\n", apath)
		}

		var resolver proxy.CredentialResolver
		if devInject {
			resolver = credential.NewResolver()
			fmt.Println("🔑 secretless credential injection enabled (broker-backed)")
		}

		fmt.Printf("🔒 Starting Nexus Security Proxy on :%d (Strict: %t, RequireAuth: %t, Policy: %t)...\n",
			proxyPort, strictMode, requireAuth, engine != nil)
		server := proxy.New(proxy.Config{
			Port:        proxyPort,
			Strict:      strictMode,
			RequireAuth: requireAuth,
			Verifier:    verifier,
			Engine:      engine,
			Audit:       auditlog,
			Replay:      replay,
			Credentials: resolver,
			OnPersistRule: func(rule policy.Rule) {
				if err := appendPolicyRule(devPolicy, rule); err != nil {
					fmt.Fprintf(os.Stderr, "note: could not persist rule to %s: %v\n", devPolicy, err)
				}
			},
		})
		return server.Start()
	},
}

func init() {
	devCmd.Flags().IntVarP(&proxyPort, "port", "p", 8075, "Port to run the local proxy on")
	devCmd.Flags().BoolVarP(&strictMode, "strict", "s", false, "Require HITL approval for all calls including GET")
	devCmd.Flags().BoolVar(&requireAuth, "require-auth", true, "Reject requests without a valid dual-actor micro-JWT (use --require-auth=false to disable)")
	devCmd.Flags().StringVar(&devKeyPath, "key", "", "Path to the persistent Ed25519 key (default ~/.nexus/ed25519.key)")
	devCmd.Flags().StringVar(&devPolicy, "policy", "nexus.yaml", "Path to the policy file")
	devCmd.Flags().BoolVar(&devNoAudit, "no-audit", false, "Disable the tamper-evident audit log")
	devCmd.Flags().BoolVar(&devInject, "inject", false, "Inject broker-issued upstream credentials for rules marked inject: true")
}
