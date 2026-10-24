package notify

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

func TestClean(t *testing.T) {
	cases := map[string]string{
		"plain":                     "plain",
		"a\nb\r\nc\td":              "a b c d",
		"\x1b[31mred\x1b[0m":        "[31mred [0m",
		"  lots   of\x00space ":     "lots of space",
		"evil\u202egnp.exe":         "evil gnp.exe",
		"zero\u200bwidth\u2028line": "zero width line",
		"bad\xffutf8":               "bad utf8",
		`quote " and \ backslash`:   `quote " and \ backslash`,
		"$(rm -rf /); `id` & | > <": "$(rm -rf /); `id` & | > <",
	}
	for in, want := range cases {
		if got := Clean(in, MaxLen); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("é", 500)
	got := Clean(long, MaxLen)
	if utf8.RuneCountInString(got) != MaxLen || !strings.HasSuffix(got, "…") || !utf8.ValidString(got) {
		t.Fatalf("truncation: %d runes", utf8.RuneCountInString(got))
	}
}

func decodePS(t *testing.T, enc string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(b)%2 != 0 {
		t.Fatalf("bad encoding: %v", err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

func TestBuildCommand(t *testing.T) {
	title := "-u low\n\"$(touch pwned)\" `x`"
	body := "<b>bold</b> & \x1b]0;evil\x07 \\\" end"

	linux, err := BuildCommand("linux", "/usr/bin/notify-send", title, body)
	if err != nil {
		t.Fatal(err)
	}
	wantLinux := []string{"--app-name=nexus-cli", "-u", "critical", "--", "-u low \"$(touch pwned)\" `x`", "&lt;b&gt;bold&lt;/b&gt; &amp; ]0;evil \\\" end"}
	if linux.Name != "/usr/bin/notify-send" || strings.Join(linux.Args, "\x00") != strings.Join(wantLinux, "\x00") || linux.Env != nil {
		t.Fatalf("linux: %#v", linux)
	}

	mac, err := BuildCommand("darwin", "", title, body)
	if err != nil {
		t.Fatal(err)
	}
	if mac.Name != "osascript" || len(mac.Args) != 2 || mac.Args[0] != "-e" {
		t.Fatalf("darwin: %#v", mac)
	}
	wantScript := `display notification "<b>bold</b> & ]0;evil \\\" end" with title "-u low \"$(touch pwned)\" ` + "`x`" + `"`
	if mac.Args[1] != wantScript {
		t.Fatalf("darwin script:\n got %s\nwant %s", mac.Args[1], wantScript)
	}

	win, err := BuildCommand("windows", `C:\Windows\powershell.exe`, title, body)
	if err != nil {
		t.Fatal(err)
	}
	if win.Name != `C:\Windows\powershell.exe` || len(win.Args) != 8 || win.Args[6] != "-EncodedCommand" {
		t.Fatalf("windows: %#v", win)
	}
	script := decodePS(t, win.Args[7])
	if script != windowsScript {
		t.Fatal("windows script must be the constant script")
	}
	for _, a := range win.Args {
		if strings.Contains(a, "pwned") || strings.Contains(a, "bold") {
			t.Fatalf("untrusted text leaked into argv: %q", a)
		}
	}
	if len(win.Env) != 2 || win.Env[0] != "NEXUS_NOTIFY_TITLE=-u low \"$(touch pwned)\" `x`" || win.Env[1] != "NEXUS_NOTIFY_BODY=<b>bold</b> & ]0;evil \\\" end" {
		t.Fatalf("windows env: %#v", win.Env)
	}
	if !strings.Contains(script, "Windows.UI.Notifications") || !strings.Contains(script, "System.Windows.Forms.NotifyIcon") || !strings.Contains(script, "$env:NEXUS_NOTIFY_TITLE") {
		t.Fatal("windows script lacks toast/balloon/env usage")
	}

	if _, err := BuildCommand("plan9", "", "t", "b"); err == nil {
		t.Fatal("unsupported OS must error")
	}
	if c, _ := BuildCommand("linux", "", "", "b"); c.Args[4] != "nexus-cli" {
		t.Fatalf("empty title: %#v", c.Args)
	}
}

func TestCommandNotifierUsesRunner(t *testing.T) {
	var got Command
	n := CommandNotifier{GOOS: "linux", Path: "notify-send", Run: func(ctx context.Context, name string, args, env []string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("runner context needs a deadline")
		}
		got = Command{name, args, env}
		return nil
	}}
	if err := n.Notify("t", "b"); err != nil {
		t.Fatal(err)
	}
	if got.Name != "notify-send" || got.Args[4] != "t" || got.Args[5] != "b" {
		t.Fatalf("%#v", got)
	}
}

func TestDetect(t *testing.T) {
	found := func(name string) (string, error) { return "/bin/" + name, nil }
	missing := func(string) (string, error) { return "", errors.New("nope") }
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	desktop := map[string]string{"DISPLAY": ":0"}

	if n, err := detect("linux", found, env(desktop)); err != nil || n.(CommandNotifier).Path != "/bin/notify-send" {
		t.Fatalf("linux: %v %v", n, err)
	}
	if _, err := detect("linux", missing, env(desktop)); err == nil {
		t.Fatal("linux without notify-send must be unavailable")
	}
	if _, err := detect("linux", found, env(nil)); err == nil {
		t.Fatal("headless linux must be unavailable")
	}
	if n, err := detect("darwin", found, env(nil)); err != nil || n.(CommandNotifier).GOOS != "darwin" {
		t.Fatalf("darwin: %v %v", n, err)
	}
	if n, err := detect("windows", found, env(nil)); err != nil || n.(CommandNotifier).Path != "/bin/powershell.exe" {
		t.Fatalf("windows: %v %v", n, err)
	}
	if n, _ := detect("darwin", found, env(map[string]string{EnvVar: "off"})); n != (Nop{}) {
		t.Fatalf("NEXUS_NOTIFY=off: %#v", n)
	}
}

func TestNewAndParseMode(t *testing.T) {
	if n, err := New("off"); err != nil || n != (Nop{}) {
		t.Fatalf("off: %v %v", n, err)
	}
	t.Setenv(EnvVar, "off")
	if n, err := New("auto"); err != nil || n != (Nop{}) {
		t.Fatalf("auto with env off: %v %v", n, err)
	}
	if _, err := New("loud"); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

// fakeNotifier records notifications.
type fakeNotifier struct {
	mu   sync.Mutex
	msgs [][2]string
	ch   chan [2]string
}

func newFake() *fakeNotifier { return &fakeNotifier{ch: make(chan [2]string, 32)} }

func (f *fakeNotifier) Notify(title, body string) error {
	f.mu.Lock()
	f.msgs = append(f.msgs, [2]string{title, body})
	f.mu.Unlock()
	f.ch <- [2]string{title, body}
	return nil
}

func (f *fakeNotifier) next(t *testing.T, within time.Duration) [2]string {
	t.Helper()
	select {
	case m := <-f.ch:
		return m
	case <-time.After(within):
		t.Fatal("no notification")
	}
	return [2]string{}
}

func (f *fakeNotifier) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-f.ch:
		t.Fatalf("unexpected notification %q", m)
	case <-time.After(d):
	}
}

func queue(t *testing.T, ctx context.Context, b *hitl.Broker, req hitl.Request) {
	t.Helper()
	n := len(b.Pending())
	go b.Approve(ctx, req)
	for len(b.Pending()) != n+1 {
		time.Sleep(time.Millisecond)
	}
}

func startWatch(t *testing.T, b *hitl.Broker, f Notifier, info Info) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { WatchBroker(ctx, b, f, info); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(20 * time.Millisecond) // let it subscribe
	return ctx
}

func TestWatchBrokerNotifiesAndCoalesces(t *testing.T) {
	b := hitl.NewBroker(time.Minute)
	f := newFake()
	interval := 300 * time.Millisecond
	ctx := startWatch(t, b, f, Info{Interval: interval})

	queue(t, ctx, b, hitl.Request{AgentID: "claude\x1b[2J", Tool: "POST", Target: "http://example.com/x\nFAKE", Reason: "matched rule"})
	m := f.next(t, time.Second)
	if m[0] != "Approval needed: claude [2J → POST http://example.com/x FAKE" || m[1] != "matched rule · Run: nexus-cli approve" {
		t.Fatalf("first: %q", m)
	}

	// A burst within the interval is coalesced into one notification after it elapses.
	start := time.Now()
	queue(t, ctx, b, hitl.Request{AgentID: "a2", Tool: "PUT"})
	queue(t, ctx, b, hitl.Request{AgentID: "a3", Tool: "DELETE"})
	m = f.next(t, 2*time.Second)
	if m[0] != "3 approvals pending" || !strings.Contains(m[1], "Oldest: claude") || !strings.Contains(m[1], "nexus-cli approve") {
		t.Fatalf("coalesced: %q", m)
	}
	if el := time.Since(start); el < interval/2 {
		t.Fatalf("coalesced notification too early: %v", el)
	}
	f.none(t, 2*interval)
}

func TestWatchBrokerSkipsDecidedAndPointsAtUI(t *testing.T) {
	b := hitl.NewBroker(time.Minute)
	f := newFake()
	active := true
	ctx := startWatch(t, b, f, Info{Interval: 200 * time.Millisecond, UIURL: "http://127.0.0.1:1/ui", UIActive: func() bool { return active }})

	queue(t, ctx, b, hitl.Request{ID: "x", AgentID: "a", Tool: "POST"})
	if m := f.next(t, time.Second); m[1] != "Open http://127.0.0.1:1/ui" {
		t.Fatalf("ui hint: %q", m)
	}
	// Queued and decided inside the interval: nothing left to announce.
	queue(t, ctx, b, hitl.Request{ID: "y", AgentID: "a", Tool: "POST"})
	_ = b.Decide("x", hitl.Deny)
	_ = b.Decide("y", hitl.Deny)
	f.none(t, 500*time.Millisecond)
}

func TestWatchBrokerNop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { WatchBroker(ctx, hitl.NewBroker(time.Minute), Nop{}, Info{}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WatchBroker with Nop should return at once")
	}
}

func TestMessage(t *testing.T) {
	if ti, bo := Message(nil, "h"); ti != "" || bo != "" {
		t.Fatal("empty")
	}
	ti, bo := Message([]hitl.Request{{Tool: strings.Repeat("x", 1000)}}, "Run: nexus-cli approve")
	if utf8.RuneCountInString(ti) > MaxLen || !strings.HasPrefix(ti, "Approval needed: agent → ") || bo != "Run: nexus-cli approve" {
		t.Fatalf("%q %q", ti, bo)
	}
}
