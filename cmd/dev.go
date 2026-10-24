package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/credential"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
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
	devListen   string
	devSingle   bool
	devTimeout  time.Duration
	devMITM     string
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

		stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
		if devTimeout <= 0 {
			return fmt.Errorf("--approval-timeout must be positive (got %s)", devTimeout)
		}
		mitmCA, err := resolveMITM(devMITM)
		if err != nil {
			return err
		}

		pol, agent, exists, err := loadPolicyOrDefault(devPolicy)
		if err != nil {
			return err
		}
		engine := policy.NewEngine(pol)
		if exists {
			fmt.Fprintf(stdout, "📜 policy loaded from %s (agent: %s)\n", devPolicy, agent)
		} else {
			fmt.Fprintf(stdout, "📜 no %s found — using the safe-tier default policy (reads allowed, writes ask, shell denied)\n", devPolicy)
		}

		var auditlog *audit.Logger
		if !devNoAudit {
			var apath string
			auditlog, apath, err = openAuditLog(devPolicy)
			if err != nil {
				return err
			}
			defer auditlog.Close()
			fmt.Fprintf(stdout, "📓 audit log: %s\n", apath)
		}

		var resolver proxy.CredentialResolver
		if devInject {
			resolver = credential.NewResolver()
			fmt.Fprintln(stdout, "🔑 secretless credential injection enabled (broker-backed)")
		}

		// Approvals: the local terminal (when interactive) races `nexus-cli approve` via the broker.
		broker := hitl.NewBroker(devTimeout)
		tty, hasTTY := hitl.NewTTYApprover(hitl.TTYOptions{Timeout: devTimeout})
		approver := hitl.Any(tty, broker)

		cfg := proxy.Config{
			Port:        proxyPort,
			Listen:      devListen,
			SingleUse:   devSingle,
			Strict:      strictMode,
			RequireAuth: requireAuth,
			Verifier:    verifier,
			Engine:      engine,
			Audit:       auditlog,
			Replay:      replay,
			Credentials: resolver,
			Approver:    approver,
			MITM:        mitmCA,
			Passthrough: pol.Egress.Passthrough,
			// Tests only: nil in production, which selects the proxy's default transport.
			UpstreamTransport: upstreamTransportHook,
			ApprovalTimeout:   devTimeout,
			OnPersistRule: func(rule policy.Rule) {
				if err := appendPolicyRule(devPolicy, rule); err != nil {
					fmt.Fprintf(os.Stderr, "note: could not persist rule to %s: %v\n", devPolicy, err)
				}
			},
		}
		server := proxy.New(cfg)

		ln, err := net.Listen("tcp", cfg.ListenAddr())
		if err != nil {
			return fmt.Errorf("listen on %s: %w", cfg.ListenAddr(), err)
		}
		addr := ln.Addr().String()
		if !isLoopbackAddr(addr) {
			fmt.Fprintf(stderr, "⚠️  WARNING: proxy is listening on non-loopback address %s — it is reachable from other machines.\n", addr)
			if !requireAuth {
				fmt.Fprintln(stderr, "⚠️  WARNING: --require-auth=false on a non-loopback address lets anyone on the network use this proxy.")
			}
		}
		tokenMode := "reusable until expiry (single_use tokens are one-shot)"
		if devSingle {
			tokenMode = "single-use"
		}
		fmt.Fprintf(stdout, "🔒 Nexus Security Proxy listening on %s (Strict: %t, RequireAuth: %t, Tokens: %s)\n",
			addr, strictMode, requireAuth, tokenMode)
		fmt.Fprintf(stdout, "   health: http://%s/_nexus/health · agents: HTTP_PROXY=http://agent:<token>@%s\n", addr, addr)
		if mitmCA != nil {
			fmt.Fprintf(stdout, "🔐 HTTPS interception: on (CA: %s, %d passthrough host pattern(s))\n", mitmCA.CertPath(), len(pol.Egress.Passthrough))
		} else {
			fmt.Fprintln(stdout, "🔐 HTTPS interception: off (HTTPS gated per host; 'nexus-cli ca init' enables per-request HTTPS policy)")
		}

		ctl, cerr := control.Start(broker, control.Info{Kind: "dev", Listen: addr, Policy: absPath(devPolicy)})
		if cerr != nil {
			fmt.Fprintf(stderr, "⚠️  approvals from other terminals unavailable: %v\n", cerr)
		} else {
			defer ctl.Close()
		}
		if hasTTY {
			fmt.Fprintln(stdout, "approvals: answer here or run 'nexus-cli approve' in another terminal")
		} else {
			fmt.Fprintln(stdout, "approvals: run 'nexus-cli approve' in another terminal (no interactive terminal here)")
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := server.Serve(ctx, ln); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "🛑 proxy stopped")
		return nil
	},
}

// isLoopbackAddr reports whether a host:port binds only the loopback interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func init() {
	devCmd.Flags().IntVarP(&proxyPort, "port", "p", 8075, "Port to run the local proxy on")
	devCmd.Flags().BoolVarP(&strictMode, "strict", "s", false, "Require HITL approval for all calls including GET")
	devCmd.Flags().BoolVar(&requireAuth, "require-auth", true, "Reject requests without a valid dual-actor micro-JWT (use --require-auth=false to disable)")
	devCmd.Flags().StringVar(&devKeyPath, "key", "", "Path to the persistent Ed25519 key (default $NEXUS_HOME/ed25519.key or ~/.nexus/ed25519.key)")
	devCmd.Flags().StringVar(&devPolicy, "policy", "nexus.yaml", "Path to the policy file")
	devCmd.Flags().BoolVar(&devNoAudit, "no-audit", false, "Disable the tamper-evident audit log")
	devCmd.Flags().StringVar(&devListen, "listen", "", "Address to bind as host:port (default 127.0.0.1:<port>; non-loopback exposes the proxy to the network)")
	devCmd.Flags().BoolVar(&devSingle, "single-use", false, "Reject any reuse of a token (default: tokens are reusable until expiry unless minted --single-use)")
	devCmd.Flags().DurationVar(&devTimeout, "approval-timeout", 60*time.Second, "How long a call waits for a human decision before it is denied")
	devCmd.Flags().StringVar(&devMITM, "mitm", "auto", "HTTPS interception: auto (on if a CA exists, see 'nexus-cli ca init'), on (create the CA if needed), off")
	devCmd.Flags().BoolVar(&devInject, "inject", false, "Inject broker-issued upstream credentials for rules marked inject: true")
}
