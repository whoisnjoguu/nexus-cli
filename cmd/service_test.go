package cmd

import (
	"bytes"
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
	"github.com/whoisnjoguu/nexus-cli/pkg/service"
)

type svcFakeRunner struct {
	mu      sync.Mutex
	calls   []string
	replies map[string]string
	fail    map[string]bool
}

func (f *svcFakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	if f.fail[key] {
		return []byte(f.replies[key]), errors.New("exit status 3")
	}
	return []byte(f.replies[key]), nil
}

func (f *svcFakeRunner) Stream(ctx context.Context, w io.Writer, name string, args ...string) error {
	out, err := f.Output(ctx, name, args...)
	_, _ = w.Write(out)
	return err
}

// setupServiceTest isolates HOME/NEXUS_HOME/XDG_CONFIG_HOME and the service hooks.
func setupServiceTest(t *testing.T, goos string) (*svcFakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("USERPROFILE", filepath.Join(root, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "home", ".config"))
	t.Setenv("NEXUS_HOME", filepath.Join(root, "nexus home"))
	t.Setenv("NEXUS_KEY_BACKEND", "")
	t.Setenv("NEXUS_GATEWAY_URL", "")
	f := &svcFakeRunner{replies: map[string]string{}, fail: map[string]bool{}}
	oldGOOS, oldExe, oldRunner, oldTmp, oldWait, oldDisc, oldLinger, oldPort :=
		serviceGOOS, serviceExecutable, serviceRunner, serviceTempDirs, serviceHealthWait, serviceDiscover, serviceLingerCheck, servicePortCheck
	serviceGOOS = goos
	serviceExecutable = func() (string, error) { return "/opt/nexus tools/bin/nexus-cli", nil }
	serviceRunner = f
	serviceTempDirs = []string{}
	serviceHealthWait = 2 * time.Second
	serviceDiscover = func() ([]control.Info, error) { return nil, nil }
	serviceLingerCheck = func() bool { return true }
	servicePortCheck = func(string) error { return nil }
	t.Cleanup(func() {
		serviceGOOS, serviceExecutable, serviceRunner, serviceTempDirs, serviceHealthWait, serviceDiscover, serviceLingerCheck, servicePortCheck =
			oldGOOS, oldExe, oldRunner, oldTmp, oldWait, oldDisc, oldLinger, oldPort
	})
	return f, root
}

func runServiceCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	c := newServiceCmd()
	var out, errb bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errb)
	c.SetArgs(args)
	c.SilenceErrors, c.SilenceUsage = true, true
	err := c.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

func TestServiceInstallDryRunLinux(t *testing.T) {
	f, root := setupServiceTest(t, "linux")
	policy := filepath.Join(root, "my proj", "nexus.yaml")
	out, _, err := runServiceCmd(t, "install", "--dry-run", "--policy", policy,
		"--env", `FOO=a "b" & <c>`, "--approval-timeout", "2m", "--", "--strict")
	if err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(root, "home", ".config", "systemd", "user", "nexus-cli.service")
	for _, want := range []string{
		"# would write " + unitPath,
		`ExecStart="/opt/nexus tools/bin/nexus-cli" dev --listen 127.0.0.1:8075 --policy "` + policy + `" --mitm auto --approval-timeout 2m0s --strict`,
		`Environment="NEXUS_HOME=` + filepath.Join(root, "nexus home") + `"`,
		`Environment="FOO=a \"b\" & <c>"`,
		"Restart=on-failure",
		"ProtectSystem=strict",
		`ReadWritePaths="-` + filepath.Join(root, "nexus home") + `"`,
		"# would write the state file " + filepath.Join(root, "nexus home", "service.json"),
		"systemctl --user daemon-reload\nsystemctl --user enable --now nexus-cli.service\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("dry-run ran commands: %q", f.calls)
	}
	if _, err := os.Stat(unitPath); !os.IsNotExist(err) {
		t.Fatalf("dry-run wrote the unit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "nexus home")); !os.IsNotExist(err) {
		t.Fatalf("dry-run created NEXUS_HOME: %v", err)
	}
}

func TestServiceInstallDryRunDarwinWindows(t *testing.T) {
	_, root := setupServiceTest(t, "darwin")
	policy := filepath.Join(root, "p&q", "nexus.yaml")
	out, _, err := runServiceCmd(t, "install", "--dry-run", "--policy", policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		filepath.Join(root, "home", "Library", "LaunchAgents", "dev.nexus-cli.plist"),
		"<string>" + filepath.Join(root, "p&amp;q", "nexus.yaml") + "</string>",
		"launchctl bootstrap gui/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("darwin dry-run lacks %q:\n%s", want, out)
		}
	}

	serviceGOOS = "windows"
	out, _, err = runServiceCmd(t, "install", "--dry-run", "--policy", policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nexus-cli-service.cmd", "schtasks /Create /SC ONLOGON /TN nexus-cli /TR", "/RL LIMITED /F", "schtasks /Run /TN nexus-cli", "< NUL >>"} {
		if !strings.Contains(out, want) {
			t.Errorf("windows dry-run lacks %q:\n%s", want, out)
		}
	}
}

func TestServiceInstallRelativePolicyMadeAbsolute(t *testing.T) {
	_, root := setupServiceTest(t, "linux")
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(proj)
	out, errOut, err := runServiceCmd(t, "install", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "--policy "+filepath.Join(proj, "nexus.yaml")) || !strings.Contains(out, "WorkingDirectory=-"+proj) {
		t.Fatalf("policy not made absolute:\n%s", out)
	}
	if !strings.Contains(errOut, "does not exist yet") {
		t.Fatalf("missing-policy warning absent: %q", errOut)
	}
}

func TestServiceInstallRefusals(t *testing.T) {
	_, root := setupServiceTest(t, "linux")
	policy := filepath.Join(root, "nexus.yaml")

	_, _, err := runServiceCmd(t, "install", "--dry-run", "--policy", policy, "--listen", "0.0.0.0:8075")
	if err == nil || !strings.Contains(err.Error(), "--allow-remote") {
		t.Fatalf("non-loopback: %v", err)
	}
	if _, _, err := runServiceCmd(t, "install", "--dry-run", "--policy", policy, "--listen", "0.0.0.0:8075", "--allow-remote"); err != nil {
		t.Fatalf("--allow-remote: %v", err)
	}

	serviceTempDirs = nil // default temp dirs: t.TempDir() counts as temporary
	_, _, err = runServiceCmd(t, "install", "--dry-run", "--policy", policy)
	if err == nil || !strings.Contains(err.Error(), "refusing") || !strings.Contains(err.Error(), "temporary") {
		t.Fatalf("temp-dir policy: %v", err)
	}
	serviceTempDirs = []string{}

	if _, _, err := runServiceCmd(t, "install", "--dry-run", "--policy", policy, "stray"); err == nil {
		t.Fatal("positional args without -- should be rejected")
	}
	if _, _, err := runServiceCmd(t, "install", "--dry-run", "--policy", policy, "--env", "UNSET_NEXUS_TEST_VAR"); err == nil {
		t.Fatal("--env of an unset variable should fail")
	}
}

func TestServiceInstallStatusUninstall(t *testing.T) {
	f, root := setupServiceTest(t, "linux")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok","service":"nexus-cli","mitm":"off"}`)
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	nexusHome := filepath.Join(root, "nexus home")

	out, _, err := runServiceCmd(t, "install", "--listen", listen, "--policy", filepath.Join(root, "nexus.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "proxy healthy") || !strings.Contains(out, "run --attach "+listen) {
		t.Fatalf("install output:\n%s", out)
	}
	if got := strings.Join(f.calls, "\n"); got != "systemctl --user daemon-reload\nsystemctl --user enable --now nexus-cli.service" {
		t.Fatalf("install argv: %q", got)
	}
	st, err := service.ReadState(filepath.Join(nexusHome, "service.json"))
	if err != nil || st.Listen != listen || st.Platform != "systemd" {
		t.Fatalf("state = %+v, %v", st, err)
	}

	show := "systemctl --user show nexus-cli.service --property=LoadState,ActiveState,SubState,MainPID,Result"
	f.replies[show] = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=777\nResult=success\n"
	serviceDiscover = func() ([]control.Info, error) {
		return []control.Info{{PID: 777, Kind: "dev", Addr: "127.0.0.1:5555", Token: "SECRET", Listen: listen}}, nil
	}
	out, _, err = runServiceCmd(t, "status", "--json")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if strings.Contains(out, "SECRET") {
		t.Fatal("status leaked the control token")
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
	if rep["running"] != true || rep["healthy"] != true || rep["listen"] != listen || rep["pid"] != float64(777) {
		t.Fatalf("status report: %s", out)
	}
	if c, _ := rep["control"].(map[string]any); c == nil || c["addr"] != "127.0.0.1:5555" {
		t.Fatalf("control entry: %s", out)
	}

	// doctor hook: installed, active and healthy.
	var msgs []string
	for _, r := range doctorServiceChecks() {
		if !r.pass {
			t.Errorf("doctor check failed: %s", r.msg)
		}
		msgs = append(msgs, r.msg)
	}
	if len(msgs) != 2 || !strings.Contains(msgs[1], "active and healthy") {
		t.Fatalf("doctor checks: %q", msgs)
	}

	out, _, err = runServiceCmd(t, "status")
	if err != nil || !strings.Contains(out, "✔ running:   active (pid 777)") || !strings.Contains(out, "✔ control:   dev pid 777") {
		t.Fatalf("status text: %v\n%s", err, out)
	}

	f.replies[show] = "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nResult=exit-code\n"
	out, _, err = runServiceCmd(t, "status")
	if !errors.Is(err, errServiceDown) || !strings.Contains(out, "✖ running:   failed — result exit-code") {
		t.Fatalf("failed status: %v\n%s", err, out)
	}
	if rs := doctorServiceChecks(); len(rs) < 2 || rs[1].pass {
		t.Fatalf("doctor should flag a failed service: %+v", rs)
	}

	f.calls = nil
	if _, _, err := runServiceCmd(t, "stop"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runServiceCmd(t, "restart"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runServiceCmd(t, "logs", "-n", "5"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, "\n"); got != "systemctl --user stop nexus-cli.service\nsystemctl --user restart nexus-cli.service\njournalctl --user -u nexus-cli.service --no-pager -o short-iso -n 5" {
		t.Fatalf("control argv: %q", got)
	}

	if _, _, err := runServiceCmd(t, "uninstall"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(nexusHome, "service.json")); !os.IsNotExist(err) {
		t.Fatalf("state file not removed: %v", err)
	}
	if rs := doctorServiceChecks(); rs != nil {
		t.Fatalf("doctor should be quiet without a service: %+v", rs)
	}
}

func TestServiceNameFlag(t *testing.T) {
	_, root := setupServiceTest(t, "linux")
	out, _, err := runServiceCmd(t, "install", "--dry-run", "--name", "nexus-cli-smoke-1", "--policy", filepath.Join(root, "nexus.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "nexus-cli-smoke-1.service") || !strings.Contains(out, "service-nexus-cli-smoke-1.json") {
		t.Fatalf("--name not applied:\n%s", out)
	}
	if _, _, err := runServiceCmd(t, "install", "--dry-run", "--name", "../x", "--policy", filepath.Join(root, "nexus.yaml")); err == nil {
		t.Fatal("invalid --name accepted")
	}
}

func TestServiceInstallPortInUse(t *testing.T) {
	_, root := setupServiceTest(t, "linux")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok","service":"nexus-cli","mitm":"off"}`)
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	if err := checkPortFree(listen); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("checkPortFree(busy nexus) = %v", err)
	}
	if err := checkPortFree("127.0.0.1:0"); err != nil {
		t.Fatalf("checkPortFree(free) = %v", err)
	}

	servicePortCheck = checkPortFree
	f := serviceRunner.(*svcFakeRunner)
	_, errOut, err := runServiceCmd(t, "install", "--dry-run", "--listen", listen, "--policy", filepath.Join(root, "nexus.yaml"))
	if err != nil || !strings.Contains(errOut, "already listening") {
		t.Fatalf("dry-run should only warn: %v %q", err, errOut)
	}
	_, _, err = runServiceCmd(t, "install", "--listen", listen, "--policy", filepath.Join(root, "nexus.yaml"))
	if err == nil || !strings.Contains(err.Error(), "already listening") || len(f.calls) != 0 {
		t.Fatalf("install on a busy port: %v, calls %q", err, f.calls)
	}
}
