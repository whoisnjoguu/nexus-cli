package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
)

func validCfg(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		Name:            DefaultName,
		Executable:      filepath.Join(dir, "bin", "nexus-cli"),
		Listen:          DefaultListen,
		Policy:          filepath.Join(dir, "proj", "nexus.yaml"),
		MITM:            "auto",
		ApprovalTimeout: time.Minute,
		NexusHome:       filepath.Join(dir, "home"),
	}
}

// noTemp disables temp-dir detection so t.TempDir() paths count as durable.
var noTemp = ValidateOptions{TempDirs: []string{}}

func TestValidateOK(t *testing.T) {
	cfg := validCfg(t)
	if err := os.MkdirAll(filepath.Dir(cfg.Policy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Policy, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	warns, err := Validate(cfg, noTemp)
	if err != nil || len(warns) != 0 {
		t.Fatalf("Validate = %v, %v", warns, err)
	}
	if got := strings.Join(cfg.Command()[1:], " "); got != "dev --listen 127.0.0.1:8075 --policy "+cfg.Policy+" --mitm auto --approval-timeout 1m0s" {
		t.Fatalf("command = %q", got)
	}
}

func TestValidateMissingPolicyWarns(t *testing.T) {
	warns, err := Validate(validCfg(t), noTemp)
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "does not exist") {
		t.Fatalf("Validate = %v, %v", warns, err)
	}
}

func TestValidateRelativePolicyRefused(t *testing.T) {
	cfg := validCfg(t)
	cfg.Policy = "nexus.yaml"
	if _, err := Validate(cfg, noTemp); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("relative policy: err = %v", err)
	}
}

func TestValidateListen(t *testing.T) {
	for _, tc := range []struct {
		listen      string
		allowRemote bool
		wantErr     string
	}{
		{"127.0.0.1:8075", false, ""},
		{"localhost:9000", false, ""},
		{"[::1]:9000", false, ""},
		{"0.0.0.0:8075", false, "not a loopback"},
		{":8075", false, "not a loopback"},
		{"192.168.1.5:8075", false, "--allow-remote"},
		{"0.0.0.0:8075", true, ""},
		{"127.0.0.1:0", false, "fixed port"},
		{"127.0.0.1", false, "host:port"},
		{"127.0.0.1:80 75", false, "invalid"},
	} {
		cfg := validCfg(t)
		cfg.Listen = tc.listen
		_, err := Validate(cfg, ValidateOptions{AllowRemote: tc.allowRemote, TempDirs: []string{}})
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.listen, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want %q", tc.listen, err, tc.wantErr)
		}
	}
}

func TestValidateTempDir(t *testing.T) {
	cfg := validCfg(t)
	tmp := filepath.Dir(cfg.Policy)
	// Policy inside a temp dir is refused.
	cfg2 := cfg
	cfg2.Executable = "/usr/local/bin/nexus-cli"
	_, err := Validate(cfg2, ValidateOptions{TempDirs: []string{tmp}})
	if err == nil || !strings.Contains(err.Error(), "refusing") || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("policy in temp dir: err = %v", err)
	}
	// So is an executable from `go run`.
	cfg3 := cfg
	_, err = Validate(cfg3, ValidateOptions{TempDirs: []string{filepath.Dir(cfg.Executable)}})
	if err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("executable in temp dir: err = %v", err)
	}
	// NEXUS_HOME in a temp dir only warns.
	warns, err := Validate(cfg, ValidateOptions{TempDirs: []string{cfg.NexusHome}})
	if err != nil || len(warns) == 0 || !strings.Contains(warns[0], "NEXUS_HOME") {
		t.Fatalf("NEXUS_HOME in temp dir: %v, %v", warns, err)
	}
	// Default temp dirs cover t.TempDir().
	if _, err := Validate(validCfg(t), ValidateOptions{}); err == nil {
		t.Fatal("t.TempDir() policy should be refused with the default temp dirs")
	}
}

func TestValidateTempDirSymlink(t *testing.T) {
	tmp := t.TempDir()
	durable := t.TempDir()
	link := filepath.Join(durable, "link")
	if err := os.Symlink(tmp, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if d, ok := InTempDir(filepath.Join(link, "sub", "nexus.yaml"), []string{tmp}); !ok || d != tmp {
		t.Fatalf("symlinked path not detected as temp: %q %v", d, ok)
	}
	if _, ok := InTempDir(filepath.Join(durable, "nexus.yaml"), []string{tmp}); ok {
		t.Fatal("durable path flagged as temp")
	}
	if _, ok := InTempDir(tmp+"-sibling/x", []string{tmp}); ok {
		t.Fatal("sibling with common prefix flagged as temp")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"env key":     func(c *Config) { c.Env = []EnvVar{{Key: "BAD-KEY", Value: "x"}} },
		"env newline": func(c *Config) { c.Env = []EnvVar{{Key: "K", Value: "a\nb"}} },
		"mitm":        func(c *Config) { c.MITM = "maybe" },
		"name":        func(c *Config) { c.Name = "../evil" },
		"arg newline": func(c *Config) { c.ExtraArgs = []string{"a\nb"} },
	} {
		cfg := validCfg(t)
		mut(&cfg)
		if _, err := Validate(cfg, noTemp); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// fakeRunner records argv and replies from a script keyed by the joined argv.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	replies map[string]fakeReply
}

type fakeReply struct {
	out string
	err error
}

func newFake() *fakeRunner { return &fakeRunner{replies: map[string]fakeReply{}} }

func (f *fakeRunner) on(argv string, out string, err error) { f.replies[argv] = fakeReply{out, err} }

func (f *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	r := f.replies[key]
	return []byte(r.out), r.err
}

func (f *fakeRunner) Stream(ctx context.Context, w io.Writer, name string, args ...string) error {
	out, err := f.Output(ctx, name, args...)
	_, _ = w.Write(out)
	return err
}

func (f *fakeRunner) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func assertCalls(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s argv:\n got %q\nwant %q", what, got, want)
	}
}

func newTestManager(t *testing.T, goos string) (Manager, *fakeRunner, Options) {
	t.Helper()
	root := t.TempDir()
	f := newFake()
	o := Options{
		Runner:     f,
		HomeDir:    filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "home", ".config"),
		NexusHome:  filepath.Join(root, "home", ".nexus"),
		UID:        501,
	}
	m, err := New(goos, o)
	if err != nil {
		t.Fatal(err)
	}
	return m, f, o
}

func TestSystemdManager(t *testing.T) {
	m, f, o := newTestManager(t, "linux")
	ctx := context.Background()
	cfg := validCfg(t)
	unitPath := filepath.Join(o.ConfigHome, "systemd", "user", "nexus-cli.service")
	if m.DefinitionPath() != unitPath || m.Platform() != "systemd" || m.LogPath() != "" {
		t.Fatalf("paths: %s %s %q", m.DefinitionPath(), m.Platform(), m.LogPath())
	}
	if err := m.Start(ctx); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Start before install: %v", err)
	}

	if err := m.Install(ctx, cfg, false); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "install", f.take(),
		"systemctl --user daemon-reload",
		"systemctl --user enable --now nexus-cli.service")
	b, err := os.ReadFile(unitPath)
	if err != nil || !strings.Contains(string(b), "ExecStart="+cfg.Executable+" dev") {
		t.Fatalf("unit not written: %v\n%s", err, b)
	}
	if err := m.Install(ctx, cfg, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("reinstall without --force: %v", err)
	}
	if err := m.Install(ctx, cfg, true); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "force install", f.take(),
		"systemctl --user daemon-reload",
		"systemctl --user enable --now nexus-cli.service",
		"systemctl --user restart nexus-cli.service")

	for _, tc := range []struct {
		op   func(context.Context) error
		argv string
	}{
		{m.Start, "systemctl --user start nexus-cli.service"},
		{m.Stop, "systemctl --user stop nexus-cli.service"},
		{m.Restart, "systemctl --user restart nexus-cli.service"},
	} {
		if err := tc.op(ctx); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, tc.argv, f.take(), tc.argv)
	}

	show := "systemctl --user show nexus-cli.service --property=LoadState,ActiveState,SubState,MainPID,Result"
	f.on(show, "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nResult=success\n", nil)
	st, err := m.Status(ctx)
	if err != nil || !st.Installed || !st.Running || st.State != "active" || st.PID != 4242 || st.Detail != "sub-state running" {
		t.Fatalf("Status = %+v, %v", st, err)
	}
	assertCalls(t, "status", f.take(), show)

	f.on("systemctl --user start nexus-cli.service", "Job failed", errors.New("exit status 1"))
	if err := m.Start(ctx); err == nil || !strings.Contains(err.Error(), "Job failed") {
		t.Fatalf("start error should carry output: %v", err)
	}
	f.take()

	if err := m.Logs(ctx, io.Discard, LogOptions{Lines: 50, Follow: true}); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "logs", f.take(), "journalctl --user -u nexus-cli.service --no-pager -o short-iso -n 50 -f")

	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "uninstall", f.take(),
		"systemctl --user disable --now nexus-cli.service",
		"systemctl --user daemon-reload",
		"systemctl --user reset-failed nexus-cli.service")
	if exists(unitPath) {
		t.Fatal("unit file not removed")
	}
	if err := m.Uninstall(ctx); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("second uninstall: %v", err)
	}
}

func TestParseSystemctlShow(t *testing.T) {
	for _, tc := range []struct {
		out     string
		running bool
		state   string
		inst    bool
		detail  string
	}{
		{"LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=10\nResult=success", true, "active", true, "sub-state running"},
		{"LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success", false, "inactive", true, "sub-state dead"},
		{"LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nResult=exit-code", false, "failed", true, "result exit-code"},
		{"LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success", false, "inactive", false, "sub-state dead, load-state not-found"},
		{"LoadState=loaded\nActiveState=activating\nSubState=auto-restart\nMainPID=0\nResult=exit-code", false, "activating", true, "sub-state auto-restart, result exit-code"},
		{"", false, "unknown", false, ""},
	} {
		st := ParseSystemctlShow(tc.out)
		if st.Running != tc.running || st.State != tc.state || st.Installed != tc.inst || st.Detail != tc.detail {
			t.Errorf("ParseSystemctlShow(%q) = %+v", tc.out, st)
		}
	}
}

func TestSystemdStatusBusError(t *testing.T) {
	m, f, _ := newTestManager(t, "linux")
	f.on("systemctl --user show nexus-cli.service --property=LoadState,ActiveState,SubState,MainPID,Result",
		"Failed to connect to bus: No medium found", errors.New("exit status 1"))
	st, err := m.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Failed to connect to bus") || st.Running {
		t.Fatalf("Status = %+v, %v", st, err)
	}
}

const launchctlPrintRunning = `gui/501/dev.nexus-cli = {
	active count = 1
	path = /Users/u/Library/LaunchAgents/dev.nexus-cli.plist
	type = LaunchAgent
	state = running

	program = /usr/local/bin/nexus-cli
	arguments = {
		/usr/local/bin/nexus-cli
		dev
	}

	pid = 812
	immediate reason = speculative
	last exit code = (never exited)

	endpoints = {
		state = active
	}
}
`

const launchctlPrintStopped = `gui/501/dev.nexus-cli = {
	active count = 0
	path = /Users/u/Library/LaunchAgents/dev.nexus-cli.plist
	type = LaunchAgent
	state = not running

	program = /usr/local/bin/nexus-cli
	runs = 3
	last exit code = 1
}
`

func TestParseLaunchctlPrint(t *testing.T) {
	st := ParseLaunchctlPrint(launchctlPrintRunning)
	if !st.Running || st.State != "running" || st.PID != 812 || st.Detail != "last exit code (never exited)" {
		t.Fatalf("running: %+v", st)
	}
	st = ParseLaunchctlPrint(launchctlPrintStopped)
	if st.Running || st.State != "not running" || st.PID != 0 || st.Detail != "last exit code 1" {
		t.Fatalf("stopped: %+v", st)
	}
}

func TestLaunchdManager(t *testing.T) {
	m, f, o := newTestManager(t, "darwin")
	ctx := context.Background()
	cfg := validCfg(t)
	plist := filepath.Join(o.HomeDir, "Library", "LaunchAgents", "dev.nexus-cli.plist")
	if m.DefinitionPath() != plist || m.LogPath() != filepath.Join(o.NexusHome, "logs", "service.log") {
		t.Fatalf("paths: %s %s", m.DefinitionPath(), m.LogPath())
	}

	if err := m.Install(ctx, cfg, false); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "install", f.take(), "launchctl bootstrap gui/501 "+plist)
	b, err := os.ReadFile(plist)
	if err != nil || !strings.Contains(string(b), "<string>"+filepath.Join(o.NexusHome, "logs", "service.log")+"</string>") {
		t.Fatalf("plist not written with the manager's log path: %v\n%s", err, b)
	}
	if fi, err := os.Stat(filepath.Dir(m.LogPath())); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("log dir: %v %v", fi, err)
	}

	// bootstrap failure falls back to load -w; a forced reinstall boots the old job out first.
	f.on("launchctl bootstrap gui/501 "+plist, "Bootstrap failed: 5: Input/output error", errors.New("exit status 5"))
	if err := m.Install(ctx, cfg, true); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "force install", f.take(),
		"launchctl bootout gui/501/dev.nexus-cli",
		"launchctl bootstrap gui/501 "+plist,
		"launchctl load -w "+plist)

	for _, tc := range []struct {
		op   func(context.Context) error
		argv string
	}{
		{m.Start, "launchctl kickstart gui/501/dev.nexus-cli"},
		{m.Stop, "launchctl kill SIGTERM gui/501/dev.nexus-cli"},
		{m.Restart, "launchctl kickstart -k gui/501/dev.nexus-cli"},
	} {
		if err := tc.op(ctx); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, tc.argv, f.take(), tc.argv)
	}

	f.on("launchctl print gui/501/dev.nexus-cli", launchctlPrintRunning, nil)
	st, err := m.Status(ctx)
	if err != nil || !st.Installed || !st.Running || st.PID != 812 {
		t.Fatalf("Status = %+v, %v", st, err)
	}
	f.on("launchctl print gui/501/dev.nexus-cli", "Could not find service \"dev.nexus-cli\" in domain for user gui: 501", errors.New("exit status 113"))
	st, err = m.Status(ctx)
	if err != nil || !st.Installed || st.Running || st.State != "not loaded" {
		t.Fatalf("Status (not loaded) = %+v, %v", st, err)
	}
	f.take()

	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "uninstall", f.take(), "launchctl bootout gui/501/dev.nexus-cli")
	if exists(plist) {
		t.Fatal("plist not removed")
	}
}

const schtasksQueryRunning = `
Folder: \
HostName:                             DESKTOP-1
TaskName:                             \nexus-cli
Next Run Time:                        N/A
Status:                               Running
Logon Mode:                           Interactive only
`

func TestParseSchtasksQuery(t *testing.T) {
	st := ParseSchtasksQuery(strings.ReplaceAll(schtasksQueryRunning, "\n", "\r\n"))
	if !st.Running || st.State != "running" || st.Detail != "next run N/A" {
		t.Fatalf("running: %+v", st)
	}
	st = ParseSchtasksQuery(strings.Replace(schtasksQueryRunning, "Running", "Ready", 1))
	if st.Running || st.State != "ready" {
		t.Fatalf("ready: %+v", st)
	}
}

func TestSchtasksManager(t *testing.T) {
	m, f, o := newTestManager(t, "windows")
	ctx := context.Background()
	cfg := validCfg(t)
	script := winJoin(o.NexusHome, "nexus-cli-service.cmd")
	if m.DefinitionPath() != script {
		t.Fatalf("definition: %s", m.DefinitionPath())
	}
	if err := m.Install(ctx, cfg, false); err != nil {
		t.Fatal(err)
	}
	create := `schtasks /Create /SC ONLOGON /TN nexus-cli /TR "` + script + `" /RL LIMITED /F`
	assertCalls(t, "install", f.take(), create, "schtasks /Run /TN nexus-cli")
	if !exists(script) {
		t.Fatal("task script not written")
	}
	if err := m.Install(ctx, cfg, true); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "force install", f.take(), "schtasks /End /TN nexus-cli", create, "schtasks /Run /TN nexus-cli")

	for _, tc := range []struct {
		op   func(context.Context) error
		argv []string
	}{
		{m.Start, []string{"schtasks /Run /TN nexus-cli"}},
		{m.Stop, []string{"schtasks /End /TN nexus-cli"}},
		{m.Restart, []string{"schtasks /End /TN nexus-cli", "schtasks /Run /TN nexus-cli"}},
	} {
		if err := tc.op(ctx); err != nil {
			t.Fatal(err)
		}
		assertCalls(t, tc.argv[0], f.take(), tc.argv...)
	}

	q := "schtasks /Query /TN nexus-cli /FO LIST"
	f.on(q, schtasksQueryRunning, nil)
	if st, err := m.Status(ctx); err != nil || !st.Running || !st.Installed {
		t.Fatalf("Status = %+v, %v", st, err)
	}
	f.on(q, "ERROR: The system cannot find the file specified.", errors.New("exit status 1"))
	if st, err := m.Status(ctx); err != nil || st.Running || st.State != "not registered" {
		t.Fatalf("Status (missing) = %+v, %v", st, err)
	}
	f.take()

	if err := m.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	assertCalls(t, "uninstall", f.take(), "schtasks /End /TN nexus-cli", "schtasks /Delete /TN nexus-cli /F")
	if exists(script) {
		t.Fatal("script not removed")
	}
}

func TestSchtasksTRLimit(t *testing.T) {
	m, _, _ := newTestManager(t, "windows")
	mm := m.(*schtasksManager)
	mm.o.NexusHome = `C:\` + strings.Repeat("x", 300)
	if _, err := m.Plan(validCfg(t)); err == nil || !strings.Contains(err.Error(), "261") {
		t.Fatalf("expected the /TR length error, got %v", err)
	}
}

func TestNewUnsupported(t *testing.T) {
	if _, err := New("plan9", Options{}); err == nil {
		t.Fatal("expected an error for plan9")
	}
	if _, err := New("linux", Options{Name: "bad name"}); err == nil {
		t.Fatal("expected an error for an invalid name")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := StatePath(dir, DefaultName)
	if filepath.Base(p) != "service.json" || filepath.Base(StatePath(dir, "smoke")) != "service-smoke.json" {
		t.Fatalf("state paths: %s %s", p, StatePath(dir, "smoke"))
	}
	in := State{Name: "nexus-cli", Platform: "systemd", Definition: "/u/x.service", Listen: "127.0.0.1:8075",
		Policy: "/p/nexus.yaml", Executable: "/bin/nexus-cli", Args: []string{"dev", "--listen", "127.0.0.1:8075"},
		NexusHome: dir, InstalledAt: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	if err := WriteState(p, in); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("state file mode: %v %v", fi, err)
	}
	out, err := ReadState(p)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(in)
	b, _ := json.Marshal(out)
	if string(a) != string(b) {
		t.Fatalf("round trip:\n%s\n%s", a, b)
	}
	if err := RemoveState(p); err != nil || exists(p) {
		t.Fatalf("RemoveState: %v", err)
	}
	if err := RemoveState(p); err != nil {
		t.Fatalf("RemoveState twice: %v", err)
	}
}

func TestCheckHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != HealthPath {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"status":"ok","service":"nexus-cli","mitm":"off"}`)
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	h := CheckHealth(context.Background(), listen)
	if !h.OK || h.MITM != "off" || h.URL != srv.URL+HealthPath {
		t.Fatalf("health = %+v", h)
	}
	if h := WaitHealthy(context.Background(), listen, time.Second); !h.OK {
		t.Fatalf("WaitHealthy = %+v", h)
	}

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok","service":"something-else"}`)
	}))
	defer other.Close()
	if h := CheckHealth(context.Background(), strings.TrimPrefix(other.URL, "http://")); h.OK || !strings.Contains(h.Error, "not a nexus-cli") {
		t.Fatalf("foreign service = %+v", h)
	}

	addr := srv.Listener.Addr().String()
	srv.Close()
	if h := CheckHealth(context.Background(), addr); h.OK || h.Error == "" {
		t.Fatalf("closed server = %+v", h)
	}
	start := time.Now()
	if h := WaitHealthy(context.Background(), addr, 300*time.Millisecond); h.OK || time.Since(start) > 3*time.Second {
		t.Fatalf("WaitHealthy on a dead address = %+v after %s", h, time.Since(start))
	}
}

func TestProbeAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:8075":   "127.0.0.1:8075",
		":8075":          "127.0.0.1:8075",
		"[::]:8075":      "[::1]:8075",
		"localhost:9":    "localhost:9",
		"127.0.0.1:8075": "127.0.0.1:8075",
	} {
		if got := ProbeAddr(in); got != want {
			t.Errorf("ProbeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchControl(t *testing.T) {
	infos := []control.Info{
		{PID: 1, Kind: "run", Listen: "127.0.0.1:8075"},
		{PID: 2, Kind: "dev", Listen: "127.0.0.1:9000"},
		{PID: 3, Kind: "dev", Listen: "127.0.0.1:8075"},
	}
	if c := MatchControl(infos, "localhost:8075", 0); c == nil || c.PID != 3 {
		t.Fatalf("by listen: %+v", c)
	}
	if c := MatchControl(infos, "127.0.0.1:1234", 2); c == nil || c.PID != 2 {
		t.Fatalf("by pid: %+v", c)
	}
	if c := MatchControl(infos, "127.0.0.1:1234", 0); c != nil {
		t.Fatalf("no match expected: %+v", c)
	}
}

func TestTailFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "service.log")
	var lines []string
	for i := 1; i <= 2000; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := TailFile(context.Background(), &b, p, LogOptions{Lines: 3}); err != nil {
		t.Fatal(err)
	}
	if b.String() != "line 1998\nline 1999\nline 2000\n" {
		t.Fatalf("tail -n 3 = %q", b.String())
	}
	b.Reset()
	if err := TailFile(context.Background(), &b, p, LogOptions{Lines: 5000}); err != nil || strings.Count(b.String(), "\n") != 2000 {
		t.Fatalf("tail -n 5000: %v, %d lines", err, strings.Count(b.String(), "\n"))
	}
	if err := TailFile(context.Background(), io.Discard, p+".missing", LogOptions{}); err == nil {
		t.Fatal("missing log should error")
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestTailFileFollow(t *testing.T) {
	old := followInterval
	followInterval = 10 * time.Millisecond
	t.Cleanup(func() { followInterval = old })

	p := filepath.Join(t.TempDir(), "service.log")
	if err := os.WriteFile(p, []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var buf syncBuf
	done := make(chan error, 1)
	go func() { done <- TailFile(ctx, &buf, p, LogOptions{Lines: 1, Follow: true}) }()

	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for buf.String() != want {
			if time.Now().After(deadline) {
				t.Fatalf("follow output = %q, want %q", buf.String(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("b\n")
	fh, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(fh, "c\n")
	fh.Close()
	waitFor("b\nc\n")
	// Truncation (log rotation by copytruncate) restarts from the top.
	if err := os.WriteFile(p, []byte("d\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor("b\nc\nd\n")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
