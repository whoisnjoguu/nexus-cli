// Package service installs and controls `nexus-cli dev` as a per-user background service:
// a systemd user unit on Linux, a launchd agent on macOS and a logon Scheduled Task on Windows.
//
// Service definitions are produced by pure functions (SystemdUnit, LaunchdPlist, WindowsScript,
// SchtasksArgs) and every platform command goes through a Runner, so the whole package is testable
// on any OS without touching the real service manager.
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultName is the service name (systemd unit nexus-cli.service, launchd label dev.nexus-cli,
// Scheduled Task nexus-cli).
const DefaultName = "nexus-cli"

// DefaultListen is the proxy address the service binds by default (dev's own default).
const DefaultListen = "127.0.0.1:8075"

// ErrNotInstalled is returned by operations that need an installed service.
var ErrNotInstalled = errors.New("service is not installed (run: nexus-cli service install)")

// EnvVar is one environment assignment for the service process.
type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Config describes the `nexus-cli dev` process the service runs.
type Config struct {
	Name            string
	Executable      string // absolute path of the nexus-cli binary
	Listen          string
	Policy          string // absolute path of the policy file
	MITM            string // auto | on | off
	ApprovalTimeout time.Duration
	ExtraArgs       []string // appended to the dev command line verbatim
	Env             []EnvVar
	NexusHome       string // resolved $NEXUS_HOME (or ~/.nexus): logs, discovery and state live here
	WorkDir         string // working directory of the service (the policy's directory)
	// Hardening adds systemd sandboxing directives (ignored by the other platforms).
	Hardening bool
}

// DevArgs returns the arguments after the executable.
func (c Config) DevArgs() []string {
	args := []string{"dev", "--listen", c.Listen, "--policy", c.Policy}
	if c.MITM != "" {
		args = append(args, "--mitm", c.MITM)
	}
	if c.ApprovalTimeout > 0 {
		args = append(args, "--approval-timeout", c.ApprovalTimeout.String())
	}
	return append(args, c.ExtraArgs...)
}

// Command returns the full argv of the service process.
func (c Config) Command() []string {
	return append([]string{c.Executable}, c.DevArgs()...)
}

var (
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ValidateOptions tunes Validate.
type ValidateOptions struct {
	AllowRemote bool
	// TempDirs overrides the directories treated as temporary (default: DefaultTempDirs()).
	TempDirs []string
}

// DefaultTempDirs returns the directories whose contents may vanish (reboots, tmp cleaners).
func DefaultTempDirs() []string {
	dirs := []string{os.TempDir()}
	switch runtime.GOOS {
	case "windows":
	case "darwin":
		dirs = append(dirs, "/tmp", "/var/tmp", "/private/tmp", "/private/var/folders", "/var/folders")
	default:
		dirs = append(dirs, "/tmp", "/var/tmp", "/dev/shm")
	}
	return dirs
}

// Validate checks cfg for a durable, safe installation. It returns non-fatal warnings, and an
// error for configurations that must not be installed.
func Validate(cfg Config, opts ValidateOptions) (warnings []string, err error) {
	if !nameRE.MatchString(cfg.Name) {
		return nil, fmt.Errorf("invalid service name %q (letters, digits, '.', '_' and '-')", cfg.Name)
	}
	if !filepath.IsAbs(cfg.Executable) {
		return nil, fmt.Errorf("executable path %q is not absolute", cfg.Executable)
	}
	if !filepath.IsAbs(cfg.Policy) {
		return nil, fmt.Errorf("policy path %q is not absolute", cfg.Policy)
	}
	if err := CheckListen(cfg.Listen, opts.AllowRemote); err != nil {
		return nil, err
	}
	switch cfg.MITM {
	case "", "auto", "on", "off":
	default:
		return nil, fmt.Errorf("--mitm must be auto, on or off (got %q)", cfg.MITM)
	}
	if cfg.ApprovalTimeout < 0 {
		return nil, fmt.Errorf("--approval-timeout must be positive (got %s)", cfg.ApprovalTimeout)
	}
	for _, e := range cfg.Env {
		if !envKeyRE.MatchString(e.Key) {
			return nil, fmt.Errorf("invalid environment variable name %q", e.Key)
		}
		if strings.ContainsAny(e.Value, "\x00\r\n") {
			return nil, fmt.Errorf("environment variable %s: value must not contain newlines or NUL", e.Key)
		}
	}
	for _, a := range cfg.Command() {
		if strings.ContainsAny(a, "\x00\r\n") {
			return nil, fmt.Errorf("argument %q must not contain newlines or NUL", a)
		}
	}

	tmp := opts.TempDirs
	if tmp == nil {
		tmp = DefaultTempDirs()
	}
	if d, ok := InTempDir(cfg.Policy, tmp); ok {
		return nil, fmt.Errorf("refusing to install: policy %s is inside the temporary directory %s and may vanish — move it somewhere durable (e.g. your project or ~/.nexus)", cfg.Policy, d)
	}
	if d, ok := InTempDir(cfg.Executable, tmp); ok {
		return nil, fmt.Errorf("refusing to install: executable %s is inside the temporary directory %s (built with 'go run'?) — install nexus-cli first", cfg.Executable, d)
	}
	if cfg.NexusHome != "" {
		if d, ok := InTempDir(cfg.NexusHome, tmp); ok {
			warnings = append(warnings, fmt.Sprintf("NEXUS_HOME %s is inside the temporary directory %s; keys, audit log and discovery files may vanish", cfg.NexusHome, d))
		}
	}
	if _, serr := os.Stat(cfg.Policy); serr != nil {
		warnings = append(warnings, fmt.Sprintf("policy %s does not exist yet; dev uses the safe-tier default policy until it is created (nexus-cli init)", cfg.Policy))
	}
	return warnings, nil
}

// CheckListen requires host:port with a fixed port, on loopback unless allowRemote.
func CheckListen(listen string, allowRemote bool) error {
	if strings.ContainsAny(listen, " \t\"'<>&%$\\") {
		return fmt.Errorf("invalid --listen %q", listen)
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("--listen wants host:port (got %q): %w", listen, err)
	}
	if p, perr := strconv.Atoi(port); perr != nil || p <= 0 || p > 65535 {
		return fmt.Errorf("--listen needs a fixed port (got %q) so clients and 'service status' can find it", port)
	}
	if !allowRemote && !IsLoopbackHost(host) {
		return fmt.Errorf("refusing to install: --listen %s is not a loopback address and would expose the proxy to the network (pass --allow-remote to override)", listen)
	}
	return nil
}

// IsLoopbackHost reports whether host names only the loopback interface.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// InTempDir reports whether p (also after resolving symlinks of its existing prefix) lies inside
// one of dirs, and which.
func InTempDir(p string, dirs []string) (string, bool) {
	cands := []string{filepath.Clean(p)}
	if r := resolveExisting(p); r != cands[0] {
		cands = append(cands, r)
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		ds := []string{filepath.Clean(d)}
		if r := resolveExisting(d); r != ds[0] {
			ds = append(ds, r)
		}
		for _, c := range cands {
			for _, dd := range ds {
				if within(c, dd) {
					return d, true
				}
			}
		}
	}
	return "", false
}

func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// resolveExisting resolves symlinks in the longest existing prefix of p.
func resolveExisting(p string) string {
	p = filepath.Clean(p)
	var rest []string
	cur := p
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(append([]string{r}, rest...)...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = append([]string{filepath.Base(cur)}, rest...)
		cur = parent
	}
}

// File is a file the installer writes.
type File struct {
	Path    string
	Content string
	Mode    os.FileMode
}

// Plan is what Install does: write Files, then run Commands in order.
type Plan struct {
	Files    []File
	Commands [][]string
}

// Status is the platform's view of the service.
type Status struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	State     string `json:"state"`
	PID       int    `json:"pid,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// LogOptions selects service log output.
type LogOptions struct {
	Lines  int
	Follow bool
}

// Manager controls the service on one platform.
type Manager interface {
	// Platform names the service manager: systemd, launchd or schtasks.
	Platform() string
	Name() string
	// DefinitionPath is the unit file, plist or task script the installer writes.
	DefinitionPath() string
	// LogPath is the service log file, or "" when logs go to the journal.
	LogPath() string
	// Plan renders what Install would do, without side effects.
	Plan(cfg Config) (Plan, error)
	Install(ctx context.Context, cfg Config, force bool) error
	Uninstall(ctx context.Context) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
	Status(ctx context.Context) (Status, error)
	Logs(ctx context.Context, w io.Writer, opts LogOptions) error
}

// Options configures New.
type Options struct {
	Name       string
	Runner     Runner
	HomeDir    string // user home (launchd agents dir)
	ConfigHome string // $XDG_CONFIG_HOME or ~/.config (systemd user units)
	NexusHome  string // log and Windows task script location
	UID        int    // launchd gui/<uid> domain
}

// New returns the Manager for goos ("linux", "darwin" or "windows").
func New(goos string, o Options) (Manager, error) {
	if o.Name == "" {
		o.Name = DefaultName
	}
	if !nameRE.MatchString(o.Name) {
		return nil, fmt.Errorf("invalid service name %q (letters, digits, '.', '_' and '-')", o.Name)
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	switch goos {
	case "linux":
		return &systemdManager{o: o}, nil
	case "darwin":
		return &launchdManager{o: o}, nil
	case "windows":
		return &schtasksManager{o: o}, nil
	}
	return nil, fmt.Errorf("nexus-cli service is not supported on %s (supported: linux, darwin, windows)", goos)
}

// DefaultOptions fills Options from the current user's environment.
func DefaultOptions(name string) (Options, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Options{}, err
	}
	cfgHome := os.Getenv("XDG_CONFIG_HOME")
	if cfgHome == "" || !filepath.IsAbs(cfgHome) {
		cfgHome = filepath.Join(home, ".config")
	}
	nh, err := NexusHome()
	if err != nil {
		return Options{}, err
	}
	return Options{Name: name, HomeDir: home, ConfigHome: cfgHome, NexusHome: nh, UID: os.Getuid()}, nil
}

// NexusHome returns the absolute $NEXUS_HOME, or ~/.nexus.
func NexusHome() (string, error) {
	if h := os.Getenv("NEXUS_HOME"); h != "" {
		return filepath.Abs(h)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".nexus"), nil
}

// writeFiles writes plan files atomically, creating missing parent directories.
func writeFiles(files []File) error {
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			return err
		}
		tmp := f.Path + ".tmp"
		if err := os.WriteFile(tmp, []byte(f.Content), f.Mode); err != nil {
			return err
		}
		if err := os.Chmod(tmp, f.Mode); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, f.Path); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

// ensureLogDir creates the directory of a log file as private (0700).
func ensureLogDir(logPath string) error {
	if logPath == "" {
		return nil
	}
	return os.MkdirAll(filepath.Dir(logPath), 0o700)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func errAlreadyInstalled(p string) error {
	return fmt.Errorf("service already installed at %s (use --force to replace it)", p)
}
