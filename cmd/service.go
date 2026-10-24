package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/service"
)

// Test hooks: tests swap these to render other platforms and avoid touching the real system.
var (
	serviceGOOS                       = runtime.GOOS
	serviceExecutable                 = currentExecutable
	serviceRunner      service.Runner = service.ExecRunner{}
	serviceTempDirs    []string       // nil: service.DefaultTempDirs()
	serviceHealthWait  = 10 * time.Second
	serviceDiscover    = control.Discover
	serviceLingerCheck = lingerEnabled
	servicePortCheck   = checkPortFree
)

// servicePropagatedEnv are copied into the service environment when set at install time: the
// service must share NEXUS_HOME (discovery, keys, CA) and the key backend with the CLI.
var servicePropagatedEnv = []string{"NEXUS_HOME", "NEXUS_KEY_BACKEND", "NEXUS_GATEWAY_URL"}

// errServiceDown makes `service status` exit non-zero after printing the report.
var errServiceDown = errors.New("service is not running or not healthy")

type serviceFlags struct {
	name        string
	listen      string
	policy      string
	mitm        string
	timeout     time.Duration
	env         []string
	force       bool
	dryRun      bool
	allowRemote bool
	noHardening bool
	json        bool
	follow      bool
	lines       int
}

func init() {
	rootCmd.AddCommand(newServiceCmd())
}

func newServiceCmd() *cobra.Command {
	f := &serviceFlags{}
	c := &cobra.Command{
		Use:   "service",
		Short: "Run 'nexus-cli dev' as a per-user background service (systemd, launchd, Task Scheduler)",
		Long: `Install, control and inspect a per-user background service that runs 'nexus-cli dev'.

Linux uses a systemd user unit, macOS a launchd agent and Windows a logon Scheduled Task. The
service shares $NEXUS_HOME with your shell, so 'nexus-cli run --attach <listen>' and
'nexus-cli approve' find it; keep NEXUS_HOME identical in both (see docs/service.md).`,
	}
	c.PersistentFlags().StringVar(&f.name, "name", service.DefaultName, "Service name (for tests and side-by-side installs)")
	_ = c.PersistentFlags().MarkHidden("name")

	install := &cobra.Command{
		Use:   "install [-- extra dev flags]",
		Short: "Install and start the service",
		Example: `  nexus-cli service install --policy ./nexus.yaml
  nexus-cli service install --dry-run
  nexus-cli service install --env NEXUS_KEY_BACKEND=file -- --strict`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
				return fmt.Errorf("unexpected argument %q (pass extra dev flags after --)", args[0])
			}
			return serviceInstall(cmd, f, args)
		},
	}
	fl := install.Flags()
	fl.StringVar(&f.listen, "listen", service.DefaultListen, "Proxy address host:port (loopback unless --allow-remote)")
	fl.StringVar(&f.policy, "policy", "", policyFlagHelp+"; stored as an absolute path")
	fl.StringVar(&f.mitm, "mitm", "auto", "HTTPS interception: auto, on or off")
	fl.DurationVar(&f.timeout, "approval-timeout", 60*time.Second, "How long a call waits for a human decision")
	fl.StringArrayVar(&f.env, "env", nil, "Extra environment KEY=VALUE for the service (KEY alone copies the current value); repeatable")
	fl.BoolVar(&f.force, "force", false, "Replace an existing installation")
	fl.BoolVar(&f.dryRun, "dry-run", false, "Print the service definition and commands without changing anything")
	fl.BoolVar(&f.allowRemote, "allow-remote", false, "Allow a non-loopback --listen address")
	fl.BoolVar(&f.noHardening, "no-hardening", false, "Linux: omit systemd sandboxing (ProtectSystem=strict etc.)")

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop, disable and remove the service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			m, nexusHome, err := serviceManagerFor(f.name, "")
			if err != nil {
				return err
			}
			if err := m.Uninstall(cmd.Context()); err != nil {
				return err
			}
			if err := service.RemoveState(service.StatePath(nexusHome, f.name)); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "🗑  service %s removed (%s)\n", f.name, m.DefinitionPath())
			return nil
		},
	}

	ctlCmd := func(use, short, done string, op func(service.Manager, context.Context) error, wait bool) *cobra.Command {
		return &cobra.Command{
			Use:   use,
			Short: short,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				m, nexusHome, err := serviceManagerFor(f.name, "")
				if err != nil {
					return err
				}
				if err := op(m, cmd.Context()); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "service %s %s\n", f.name, done)
				if !wait {
					return nil
				}
				listen := serviceListen(m, nexusHome, f.name)
				h := service.WaitHealthy(cmd.Context(), listen, serviceHealthWait)
				if !h.OK {
					return fmt.Errorf("proxy not healthy at %s: %s (see: nexus-cli service logs)", h.URL, h.Error)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✔ proxy healthy at %s\n", h.URL)
				return nil
			},
		}
	}
	start := ctlCmd("start", "Start the service", "started", service.Manager.Start, true)
	stop := ctlCmd("stop", "Stop the service", "stopped", service.Manager.Stop, false)
	restart := ctlCmd("restart", "Restart the service", "restarted", service.Manager.Restart, true)

	status := &cobra.Command{
		Use:   "status",
		Short: "Show service state, proxy health and the control endpoint (exit 1 if not running)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serviceStatus(cmd, f)
		},
	}
	status.Flags().BoolVar(&f.json, "json", false, "Print the report as JSON")

	logs := &cobra.Command{
		Use:   "logs",
		Short: "Show service logs (journalctl on Linux, the service log file elsewhere)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			m, _, err := serviceManagerFor(f.name, "")
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
			defer stop()
			if m.Platform() == "schtasks" {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: Windows has no service journal; showing %s (written by the task script)\n", m.LogPath())
			}
			return m.Logs(ctx, cmd.OutOrStdout(), service.LogOptions{Lines: f.lines, Follow: f.follow})
		},
	}
	logs.Flags().BoolVarP(&f.follow, "follow", "f", false, "Keep printing new log lines")
	logs.Flags().IntVarP(&f.lines, "lines", "n", 100, "Number of recent lines to show (0: all)")

	c.AddCommand(install, uninstall, start, stop, restart, status, logs)
	return c
}

// serviceManagerFor builds the platform manager. nexusHome overrides the NEXUS_HOME it uses for
// logs and state (install passes the service's own NEXUS_HOME).
func serviceManagerFor(name, nexusHome string) (service.Manager, string, error) {
	o, err := service.DefaultOptions(name)
	if err != nil {
		return nil, "", err
	}
	if nexusHome != "" {
		o.NexusHome = nexusHome
	}
	o.Runner = serviceRunner
	m, err := service.New(serviceGOOS, o)
	if err != nil {
		return nil, "", err
	}
	return m, o.NexusHome, nil
}

// currentExecutable returns the absolute path of this binary, preferring the path it was invoked
// by (e.g. a stable /usr/local/bin symlink) over the resolved target when both are the same file,
// so package-manager upgrades keep the service working.
func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return "", err
	}
	if p, lerr := exec.LookPath(os.Args[0]); lerr == nil {
		if ap, aerr := filepath.Abs(p); aerr == nil {
			a, e1 := os.Stat(ap)
			b, e2 := os.Stat(exe)
			if e1 == nil && e2 == nil && os.SameFile(a, b) {
				return ap, nil
			}
		}
	}
	return exe, nil
}

// serviceEnv merges propagated variables with --env entries (later entries win).
func serviceEnv(flags []string) ([]service.EnvVar, error) {
	var env []service.EnvVar
	set := func(k, v string) {
		for i := range env {
			if env[i].Key == k {
				env[i].Value = v
				return
			}
		}
		env = append(env, service.EnvVar{Key: k, Value: v})
	}
	for _, k := range servicePropagatedEnv {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			set(k, v)
		}
	}
	for _, kv := range flags {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			cur, found := os.LookupEnv(kv)
			if !found {
				return nil, fmt.Errorf("--env %s: not set in the current environment (use KEY=VALUE)", kv)
			}
			v = cur
		}
		if k == "" {
			return nil, fmt.Errorf("--env %q: missing variable name", kv)
		}
		set(k, v)
	}
	for i := range env {
		if env[i].Key == "NEXUS_HOME" {
			abs, err := filepath.Abs(env[i].Value)
			if err != nil {
				return nil, err
			}
			env[i].Value = abs
		}
	}
	return env, nil
}

func serviceInstall(cmd *cobra.Command, f *serviceFlags, extra []string) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	exe, err := serviceExecutable()
	if err != nil {
		return fmt.Errorf("locate nexus-cli executable: %w", err)
	}
	policyPath, err := filepath.Abs(resolvePolicyPath(cmd))
	if err != nil {
		return err
	}
	env, err := serviceEnv(f.env)
	if err != nil {
		return err
	}
	shellHome, err := service.NexusHome()
	if err != nil {
		return err
	}
	nexusHome := shellHome
	for _, e := range env {
		if e.Key == "NEXUS_HOME" {
			nexusHome = e.Value
		}
	}
	if f.timeout <= 0 {
		return fmt.Errorf("--approval-timeout must be positive (got %s)", f.timeout)
	}
	cfg := service.Config{
		Name:            f.name,
		Executable:      exe,
		Listen:          f.listen,
		Policy:          policyPath,
		MITM:            f.mitm,
		ApprovalTimeout: f.timeout,
		ExtraArgs:       extra,
		Env:             env,
		NexusHome:       nexusHome,
		WorkDir:         filepath.Dir(policyPath),
		Hardening:       !f.noHardening,
	}
	warnings, err := service.Validate(cfg, service.ValidateOptions{AllowRemote: f.allowRemote, TempDirs: serviceTempDirs})
	if err != nil {
		return err
	}
	if nexusHome != shellHome {
		warnings = append(warnings, fmt.Sprintf("the service uses NEXUS_HOME=%s but this shell uses %s; 'run --attach' and 'approve' only find the service with the same NEXUS_HOME", nexusHome, shellHome))
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "⚠️  %s\n", w)
	}

	m, _, err := serviceManagerFor(f.name, nexusHome)
	if err != nil {
		return err
	}
	statePath := service.StatePath(nexusHome, f.name)

	// A replaced service still holds its own port, so --force skips the check.
	var portErr error
	if !f.force {
		portErr = servicePortCheck(cfg.Listen)
	}

	if f.dryRun {
		if portErr != nil {
			fmt.Fprintf(stderr, "⚠️  %v\n", portErr)
		}
		plan, err := m.Plan(cfg)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "# dry run: nothing is written or started (%s)\n", m.Platform())
		for _, file := range plan.Files {
			fmt.Fprintf(stdout, "# would write %s (mode %04o):\n%s", file.Path, file.Mode, file.Content)
			if !strings.HasSuffix(file.Content, "\n") {
				fmt.Fprintln(stdout)
			}
		}
		fmt.Fprintf(stdout, "# would write the state file %s\n", statePath)
		fmt.Fprintln(stdout, "# would run:")
		for _, c := range plan.Commands {
			fmt.Fprintln(stdout, service.ShellJoin(c))
		}
		return nil
	}

	if portErr != nil {
		return portErr
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	// Must exist before start: the hardened unit only makes existing paths writable.
	if err := os.MkdirAll(nexusHome, 0o700); err != nil {
		return err
	}
	if err := m.Install(ctx, cfg, f.force); err != nil {
		return err
	}
	if err := service.WriteState(statePath, service.State{
		Name:        f.name,
		Platform:    m.Platform(),
		Definition:  m.DefinitionPath(),
		Listen:      cfg.Listen,
		Policy:      cfg.Policy,
		Executable:  cfg.Executable,
		Args:        cfg.DevArgs(),
		NexusHome:   nexusHome,
		InstalledAt: time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("service installed, but writing %s failed: %w", statePath, err)
	}
	fmt.Fprintf(stdout, "✔ installed %s service %s (%s)\n", m.Platform(), f.name, m.DefinitionPath())

	h := service.WaitHealthy(ctx, cfg.Listen, serviceHealthWait)
	if h.OK {
		fmt.Fprintf(stdout, "✔ proxy healthy at %s\n", h.URL)
	} else {
		fmt.Fprintf(stderr, "⚠️  proxy not healthy yet at %s: %s — check: nexus-cli service logs\n", h.URL, h.Error)
	}
	fmt.Fprintf(stdout, "  gate a command:  nexus-cli run --attach %s -- <cmd>\n", cfg.Listen)
	fmt.Fprintln(stdout, "  answer approvals: nexus-cli approve")
	if m.Platform() == "systemd" && !serviceLingerCheck() {
		fmt.Fprintln(stdout, "  note: user services stop at logout; to keep it running run: loginctl enable-linger $USER")
	}
	return nil
}

// checkPortFree fails when something already listens on listen (the service would crash-loop).
func checkPortFree(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err == nil {
		return ln.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if h := service.CheckHealth(ctx, listen); h.OK {
		return fmt.Errorf("a nexus-cli proxy is already listening on %s (stop it, or pick another --listen; use --force when replacing this service)", listen)
	}
	return fmt.Errorf("cannot use --listen %s: %w", listen, err)
}

// lingerEnabled reports whether systemd keeps this user's services running without a session.
func lingerEnabled() bool {
	u, err := user.Current()
	if err != nil {
		return true
	}
	_, err = os.Stat(filepath.Join("/var/lib/systemd/linger", u.Username))
	return err == nil
}

// serviceListen finds the proxy address: state file, then the installed definition, then the default.
func serviceListen(m service.Manager, nexusHome, name string) string {
	if st, err := service.ReadState(service.StatePath(nexusHome, name)); err == nil && st.Listen != "" {
		return st.Listen
	}
	if b, err := os.ReadFile(m.DefinitionPath()); err == nil {
		if l := service.ListenFromDefinition(string(b)); l != "" {
			return l
		}
	}
	return service.DefaultListen
}

type serviceReport struct {
	Name       string `json:"name"`
	Platform   string `json:"platform"`
	Definition string `json:"definition"`
	NexusHome  string `json:"nexus_home"`
	service.Status
	StatusError string         `json:"status_error,omitempty"`
	Listen      string         `json:"listen"`
	Health      service.Health `json:"health"`
	Control     *control.Info  `json:"control,omitempty"`
	StateFile   *service.State `json:"state_file,omitempty"`
	Healthy     bool           `json:"healthy"`
}

// collectServiceReport gathers platform state, proxy health and the dev discovery entry.
func collectServiceReport(ctx context.Context, name string) (serviceReport, error) {
	m, nexusHome, err := serviceManagerFor(name, "")
	if err != nil {
		return serviceReport{}, err
	}
	r := serviceReport{Name: name, Platform: m.Platform(), Definition: m.DefinitionPath(), NexusHome: nexusHome}
	st, serr := m.Status(ctx)
	r.Status = st
	if serr != nil {
		r.StatusError = serr.Error()
	}
	if s, err := service.ReadState(service.StatePath(nexusHome, name)); err == nil {
		r.StateFile = &s
	}
	r.Listen = serviceListen(m, nexusHome, name)
	r.Health = service.CheckHealth(ctx, r.Listen)
	if infos, err := serviceDiscover(); err == nil {
		if ci := service.MatchControl(infos, r.Listen, st.PID); ci != nil {
			c := *ci
			c.Token = "" // never print the control bearer token
			r.Control = &c
		}
	}
	r.Healthy = r.Running && r.Health.OK
	return r, nil
}

func serviceStatus(cmd *cobra.Command, f *serviceFlags) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	r, err := collectServiceReport(ctx, f.name)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if f.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else {
		printServiceReport(out, r)
	}
	if !r.Healthy {
		return errServiceDown
	}
	return nil
}

func printServiceReport(w io.Writer, r serviceReport) {
	mark := func(ok bool) string {
		if ok {
			return "✔"
		}
		return "✖"
	}
	fmt.Fprintf(w, "service:   %s (%s)\n", r.Name, r.Platform)
	if !r.Installed {
		fmt.Fprintf(w, "%s installed: no (%s)\n", mark(false), r.Definition)
	} else {
		fmt.Fprintf(w, "%s installed: %s\n", mark(true), r.Definition)
	}
	state := r.Status.State
	if r.PID > 0 {
		state += fmt.Sprintf(" (pid %d)", r.PID)
	}
	if r.Detail != "" {
		state += " — " + r.Detail
	}
	fmt.Fprintf(w, "%s running:   %s\n", mark(r.Running), state)
	if r.StatusError != "" {
		fmt.Fprintf(w, "  status error: %s\n", r.StatusError)
	}
	if r.Health.OK {
		fmt.Fprintf(w, "%s health:    %s (mitm %s)\n", mark(true), r.Health.URL, r.Health.MITM)
	} else {
		fmt.Fprintf(w, "%s health:    %s: %s\n", mark(false), r.Health.URL, r.Health.Error)
	}
	if r.Control != nil {
		fmt.Fprintf(w, "%s control:   dev pid %d at %s (approvals: nexus-cli approve)\n", mark(true), r.Control.PID, r.Control.Addr)
	} else {
		fmt.Fprintf(w, "%s control:   no dev discovery entry in %s/control (NEXUS_HOME must match the service's)\n", mark(false), r.NexusHome)
	}
	if r.StateFile != nil && r.StateFile.Policy != "" {
		fmt.Fprintf(w, "  policy:   %s\n", r.StateFile.Policy)
	}
}
