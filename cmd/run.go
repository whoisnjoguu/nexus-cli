package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/credential"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/notify"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/proxy"
)

var (
	runAgentID      string
	runScopes       string
	runTTL          time.Duration
	runPolicy       string
	runStrict       bool
	runInject       bool
	runMITM         string
	runAttach       string
	runNoProxy      string
	runTimeout      time.Duration
	runNotify       string
	runNoAudit      bool
	runKey          string
	runPrintEnv     bool
	runUserID       string
	runNoReload     bool
	runAcceptChange bool
	runEphemeral    bool
)

// caBundleEnv are the variables pointed at the system+nexus CA bundle so common runtimes trust
// intercepted HTTPS. NODE_EXTRA_CA_CERTS (additive) gets the CA certificate alone.
var caBundleEnv = []string{
	"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "AWS_CA_BUNDLE",
	"PIP_CERT", "CARGO_HTTP_CAINFO", "DENO_CERT", "HEX_CACERTS_PATH",
}

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run any agent or tool behind the nexus gate (proxy, token and CA trust set up automatically)",
	Long: `Run a command with all of its HTTP(S) traffic gated by nexus.

nexus-cli run starts a private proxy on 127.0.0.1 (or reuses a running 'nexus-cli dev' with
--attach), mints a dual-actor token for the command, and launches it with HTTP_PROXY/HTTPS_PROXY
pointing at the proxy. When HTTPS interception is on (see 'nexus-cli ca init'), the CA bundle
variables (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, ...) are set so the command
trusts the interception certificate without touching the system trust store.

Approval prompts never draw on this terminal (the command owns it): answer them from another
terminal with 'nexus-cli approve'. nexus-cli run exits with the command's exit status.

Examples:
  nexus-cli run -- claude
  nexus-cli run --agent-id research-bot --scopes read -- python agent.py
  nexus-cli run -- curl -sS https://api.github.com/zen
  eval "$(nexus-cli run --attach 127.0.0.1:8075 --print-env)"`,
	RunE: runRun,
}

func runRun(cmd *cobra.Command, args []string) error {
	stderr := cmd.ErrOrStderr()
	if runPrintEnv && runAttach == "" {
		return errors.New("--print-env requires --attach (an in-process proxy stops when nexus-cli exits)")
	}
	if !runPrintEnv && len(args) == 0 {
		return errors.New("missing command: nexus-cli run [flags] -- <command> [args...]")
	}
	if os.Getenv("NEXUS_RUN") == "1" && runAttach == "" {
		return errors.New("already running under 'nexus-cli run' (NEXUS_RUN=1); refusing to nest gates — use --attach to reuse a running proxy")
	}
	if runTTL <= 0 {
		return fmt.Errorf("--ttl must be positive (got %s)", runTTL)
	}
	if runTimeout <= 0 {
		return fmt.Errorf("--approval-timeout must be positive (got %s)", runTimeout)
	}
	if _, err := notify.ParseMode(runNotify); err != nil {
		return err
	}
	if runMITM != "auto" && runMITM != "on" && runMITM != "off" {
		return fmt.Errorf("--mitm must be auto, on or off (got %q)", runMITM)
	}

	rt, err := loadPolicyRuntime(resolvePolicyPath(cmd), runtimeOptions{AcceptPolicyChange: runAcceptChange, NoAudit: runNoAudit})
	if err != nil {
		return err
	}
	defer rt.Close()
	if runAttach == "" {
		warnPolicyInWorkspace(cmd.ErrOrStderr(), rt.Path)
	}
	pol, polExists := rt.Policy, rt.Exists

	agent := runAgentID
	if agent == "" {
		if len(args) > 0 {
			agent = strings.TrimSuffix(filepath.Base(args[0]), ".exe")
		} else {
			agent = "agent"
		}
	}

	actAs, ceiling, connID, gateway := runResolveActor(stderr)
	scopeList := policyScopes(pol)
	if cmd.Flags().Changed("scopes") {
		scopeList = splitList(runScopes)
	}
	if len(ceiling) > 0 {
		scopeList = (&principalCap{ceiling}).cap(scopeList)
	}

	keyPath, err := resolveKeyPath(runKey)
	if err != nil {
		return err
	}
	signer, err := jwt.LoadOrCreateSigner(keyPath)
	if err != nil {
		return err
	}
	token, err := signer.Mint(jwt.MintOptions{
		AgentID: agent,
		UserID:  actAs,
		Scopes:  scopeList,
		ConnID:  connID,
		Gateway: gateway,
		TTL:     runTTL,
	})
	if err != nil {
		return fmt.Errorf("mint token: %w", err)
	}

	var (
		proxyAddr string
		mitmCA    *ca.CA
		shutdown  = func() {}
	)
	if runAttach != "" {
		proxyAddr, mitmCA, err = attachProxy(runAttach, token)
		if err != nil {
			return err
		}
		if cmd.Flags().Changed("mitm") {
			fmt.Fprintln(stderr, "[nexus] note: --mitm is ignored with --attach; interception follows the attached proxy")
		}
	} else {
		mitmCA, err = resolveMITM(runMITM)
		if err != nil {
			return err
		}
		proxyAddr, shutdown, err = startRunProxy(rt, signer, mitmCA, stderr)
		if err != nil {
			return err
		}
		if !polExists {
			fmt.Fprintf(stderr, "[nexus] no %s found — using the safe-tier default policy\n", rt.Path)
		}
	}
	defer shutdown()

	env, err := gateEnv(proxyAddr, token, runNoProxy, mitmCA)
	if err != nil {
		return err
	}

	if runPrintEnv {
		out := cmd.OutOrStdout()
		for _, kv := range env {
			fmt.Fprintf(out, "export %s=%s\n", kv[0], shellQuote(kv[1]))
		}
		return nil
	}

	name := filepath.Base(args[0])
	if mitmCA != nil {
		fmt.Fprintf(stderr, "[nexus] HTTPS interception on (CA %s)\n", mitmCA.CertPath())
	} else {
		fmt.Fprintln(stderr, "[nexus] HTTPS interception off — HTTPS is gated per host only ('nexus-cli ca init' enables per-request policy)")
	}
	fmt.Fprintf(stderr, "[nexus] gating %s via %s — approve prompts with: nexus-cli approve\n", name, proxyAddr)

	return runChild(cmd, args, mergeEnv(os.Environ(), env))
}

// runResolveActor picks act_as: the logged-in principal, else --user-id, else an unverified
// <os user>@<hostname> with a warning.
func runResolveActor(warn io.Writer) (actAs string, ceiling []string, connID, gateway string) {
	if p, err := loadPrincipal(); err == nil && p != nil && p.Valid() {
		return p.Subject, p.Scopes, p.ConnectionID, p.GatewayURL
	}
	if runUserID != "" {
		return runUserID, nil, "", ""
	}
	actAs = localActor()
	fmt.Fprintf(warn, "[nexus] warning: not logged in; attributing calls to %s (unverified) — run 'nexus-cli login' or pass --user-id\n", actAs)
	return actAs, nil, "", ""
}

// startRunProxy serves an authenticated in-process proxy on 127.0.0.1:0 whose approvals go only to
// the broker (exposed to `nexus-cli approve` via the control API).
func startRunProxy(rt *policyRuntime, signer *jwt.TokenSigner, mitmCA *ca.CA, stderr io.Writer) (string, func(), error) {
	pol := rt.Policy
	var auditlog *audit.Logger
	if !runNoAudit {
		var err error
		if auditlog, _, err = rt.openAudit(); err != nil {
			return "", nil, err
		}
	}
	replay, err := rt.persistState(runEphemeral)
	if err != nil {
		if auditlog != nil {
			_ = auditlog.Close()
		}
		return "", nil, err
	}
	if !runNoReload {
		// SIGHUP is relayed to the child by runChild, so only file changes trigger a reload.
		rt.watch(auditlog, stderr, true)
	}
	var resolver proxy.CredentialResolver
	if runInject {
		resolver = credential.NewResolver()
	}

	broker := hitl.NewBroker(runTimeout)
	approver := hitl.ApproverFunc(func(ctx context.Context, req hitl.Request) hitl.Decision {
		fmt.Fprintf(stderr, "\n[nexus] approval needed: %s %s (%s) — run: nexus-cli approve\n",
			hitl.Sanitize(req.Tool), hitl.Truncate(hitl.Sanitize(req.Target), 120), hitl.Sanitize(req.Reason))
		return broker.Approve(ctx, req)
	})

	policyPath := rt.Path
	server := proxy.New(proxy.Config{
		Listen:            "127.0.0.1:0",
		Strict:            runStrict,
		RequireAuth:       true,
		Verifier:          signer.Verifier(),
		Engine:            rt.Engine,
		Audit:             auditlog,
		Replay:            replay,
		Credentials:       resolver,
		Approver:          approver,
		ApprovalTimeout:   runTimeout,
		MITM:              mitmCA,
		Passthrough:       pol.Egress.Passthrough,
		UpstreamTransport: upstreamTransportHook,
		OnPersistRule: func(rule policy.Rule) {
			if err := appendPolicyRule(policyPath, rule); err != nil {
				fmt.Fprintf(stderr, "[nexus] note: could not persist rule to %s: %v\n", policyPath, err)
			}
		},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		rt.Close()
		if auditlog != nil {
			_ = auditlog.Close()
		}
		return "", nil, fmt.Errorf("listen: %w", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, ln) }()

	ctl, cerr := control.Start(broker, control.Info{Kind: "run", Listen: addr, Policy: absPath(policyPath)})
	if cerr != nil {
		fmt.Fprintf(stderr, "[nexus] warning: approvals unavailable (%v); calls needing approval will be denied\n", cerr)
	}
	stopNotify, nerr := startApprovalNotifier(runNotify, broker, ctl, stderr)
	if nerr != nil {
		stopNotify = func() {}
		fmt.Fprintf(stderr, "[nexus] notifications disabled: %v\n", nerr)
	}
	shutdown := func() {
		rt.Close()
		cancel()
		if err := <-served; err != nil {
			fmt.Fprintf(stderr, "[nexus] proxy shutdown: %v\n", err)
		}
		stopNotify()
		if ctl != nil {
			_ = ctl.Close()
		}
		if auditlog != nil {
			if err := auditlog.Close(); err != nil {
				fmt.Fprintf(stderr, "[nexus] audit close: %v\n", err)
			}
		}
	}
	return addr, shutdown, nil
}

// attachProxy verifies a running `nexus-cli dev` via its health endpoint (including that it
// accepts our token) and loads the CA it intercepts with, if any.
func attachProxy(addr, token string) (string, *ca.CA, error) {
	addr = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://"), "/")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", nil, fmt.Errorf("--attach wants host:port (got %q): %w", addr, err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+proxy.HealthPath, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+token)
	hc := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("no nexus proxy at %s (start one with 'nexus-cli dev'): %w", addr, err)
	}
	defer resp.Body.Close()
	var h map[string]string
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h) != nil || h["service"] != "nexus-cli" {
		return "", nil, fmt.Errorf("%s is not a nexus proxy (health check returned %s)", addr, resp.Status)
	}
	if h["token"] == "invalid" {
		return "", nil, fmt.Errorf("the proxy at %s rejected our token: it uses a different signing key (pass the same --key as 'nexus-cli dev')", addr)
	}
	if h["mitm"] != "on" {
		return addr, nil, nil
	}
	dir, err := ca.DefaultDir()
	if err != nil {
		return "", nil, err
	}
	c, err := ca.Load(dir)
	if err != nil {
		return "", nil, fmt.Errorf("the proxy at %s intercepts HTTPS but its CA is not readable here: %w", addr, err)
	}
	if fp := h["ca_fingerprint"]; fp != "" && fp != c.Fingerprint() {
		return "", nil, fmt.Errorf("the proxy at %s intercepts HTTPS with a different CA than %s", addr, c.CertPath())
	}
	return addr, c, nil
}

// gateEnv returns the ordered variables that route a child through the proxy and, with a CA, make
// it trust intercepted HTTPS.
func gateEnv(proxyAddr, token, noProxy string, mitmCA *ca.CA) ([][2]string, error) {
	proxyURL := "http://nexus:" + token + "@" + proxyAddr
	env := [][2]string{
		{"HTTP_PROXY", proxyURL},
		{"HTTPS_PROXY", proxyURL},
		{"http_proxy", proxyURL},
		{"https_proxy", proxyURL},
		{"NO_PROXY", noProxy},
		{"no_proxy", noProxy},
		{"NODE_USE_ENV_PROXY", "1"},
		{"NEXUS_PROXY_URL", proxyURL},
		{"NEXUS_RUN", "1"},
	}
	if mitmCA != nil {
		bundle := mitmCA.BundlePath()
		if err := mitmCA.WriteBundle(bundle); err != nil {
			return nil, err
		}
		for _, k := range caBundleEnv {
			env = append(env, [2]string{k, bundle})
		}
		env = append(env, [2]string{"NODE_EXTRA_CA_CERTS", mitmCA.CertPath()})
	}
	return env, nil
}

// mergeEnv overlays vars on base, replacing existing keys (case-insensitively on Windows).
func mergeEnv(base []string, vars [][2]string) []string {
	norm := func(k string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(k)
		}
		return k
	}
	override := make(map[string]bool, len(vars))
	for _, kv := range vars {
		override[norm(kv[0])] = true
	}
	out := make([]string, 0, len(base)+len(vars))
	for _, e := range base {
		k, _, _ := strings.Cut(e, "=")
		if !override[norm(k)] {
			out = append(out, e)
		}
	}
	seen := map[string]bool{}
	for _, kv := range vars {
		if runtime.GOOS == "windows" && seen[norm(kv[0])] {
			continue // http_proxy and HTTP_PROXY are the same variable on Windows
		}
		seen[norm(kv[0])] = true
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}

// shellQuote single-quotes v for POSIX shells.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// runChild runs the command with inherited stdio, relaying termination signals, and returns an
// exitCodeError carrying its exit status when it is non-zero.
func runChild(cmd *cobra.Command, args []string, env []string) error {
	c := exec.Command(args[0], args[1:]...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()

	// Keep the parent (and so the proxy) alive until the child exits. Terminal SIGINT already
	// reaches the child through the shared foreground process group, so it is swallowed here
	// rather than delivered twice; SIGTERM/SIGHUP sent to nexus-cli are relayed.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := c.Start(); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "[nexus] cannot start %s: %v\n", args[0], err)
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return exitCodeError{127}
		}
		return exitCodeError{126}
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == os.Interrupt {
					continue
				}
				if runtime.GOOS == "windows" {
					_ = c.Process.Kill()
				} else {
					_ = c.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()

	err := c.Wait()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return err
	}
	code := ee.ExitCode()
	if code < 0 {
		code = 1
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	}
	return exitCodeError{code}
}

func init() {
	f := runCmd.Flags()
	f.SetInterspersed(false) // everything after the command name belongs to the command
	f.StringVarP(&runAgentID, "agent-id", "a", "", "Agent ID for the token (default: the command's base name)")
	f.StringVarP(&runScopes, "scopes", "s", "", "Comma-separated scopes (default: every scope required by the policy, capped by your login ceiling)")
	f.DurationVar(&runTTL, "ttl", 12*time.Hour, "Token lifetime, i.e. the maximum run duration")
	f.StringVar(&runPolicy, "policy", "", policyFlagHelp+" (falls back to the safe-tier default)")
	f.BoolVar(&runStrict, "strict", false, "Require approval for every call, including ones the policy allows")
	f.BoolVar(&runInject, "inject", false, "Inject broker-issued upstream credentials for rules marked inject: true")
	f.StringVar(&runMITM, "mitm", "auto", "HTTPS interception: auto (on if a CA exists), on (create the CA if needed), off")
	f.StringVar(&runAttach, "attach", "", "Use a running 'nexus-cli dev' at host:port instead of an in-process proxy")
	f.StringVar(&runNoProxy, "no-proxy", "localhost,127.0.0.1,::1", "NO_PROXY value for the command")
	addNotifyFlag(f, &runNotify)
	f.DurationVar(&runTimeout, "approval-timeout", 120*time.Second, "How long a call waits for 'nexus-cli approve' before it is denied")
	f.BoolVar(&runNoAudit, "no-audit", false, "Disable the tamper-evident audit log")
	f.StringVar(&runKey, "key", "", "Path to the persistent Ed25519 key (default $NEXUS_HOME/ed25519.key or ~/.nexus/ed25519.key)")
	f.BoolVar(&runPrintEnv, "print-env", false, "With --attach: print 'export' lines for eval instead of running a command")
	f.BoolVar(&runNoReload, "no-reload", false, "Disable policy hot reload")
	f.BoolVar(&runEphemeral, "ephemeral-state", false, "Keep replay, one_time and taint state in memory only (lost on restart)")
	f.BoolVar(&runAcceptChange, "accept-policy-change", false, "Accept (and re-pin) a policy whose sha256 differs from $NEXUS_HOME/policy.pin")
	f.StringVarP(&runUserID, "user-id", "u", "", "Human principal fallback when not logged in")
	rootCmd.AddCommand(runCmd)
}
