// Package notify sends best-effort desktop notifications (for example "approval needed") without
// ever invoking a shell. Every string is treated as untrusted: control and bidi-override characters
// are stripped, text is truncated, and it reaches the platform tool only as an argv element, an
// escaped string literal, or an environment variable.
package notify

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxLen is the maximum length, in runes, of a notification title or body.
const MaxLen = 200

// EnvVar selects the notification mode: "auto" (default) or "off".
const EnvVar = "NEXUS_NOTIFY"

// commandTimeout bounds each helper process.
const commandTimeout = 15 * time.Second

// Notifier shows a desktop notification.
type Notifier interface {
	Notify(title, body string) error
}

// Nop discards notifications.
type Nop struct{}

// Notify does nothing.
func (Nop) Notify(string, string) error { return nil }

// Func adapts a function to Notifier.
type Func func(title, body string) error

// Notify calls f.
func (f Func) Notify(title, body string) error { return f(title, body) }

// Runner executes a helper program with exactly these arguments and extra environment variables
// (appended to the current environment). It is injectable for tests.
type Runner func(ctx context.Context, name string, args, env []string) error

// ExecRunner runs the program with os/exec (never through a shell).
func ExecRunner(ctx context.Context, name string, args, env []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("notify: %s: %w: %s", name, err, Clean(string(out), MaxLen))
	}
	return nil
}

// Command is a fully constructed helper invocation.
type Command struct {
	Name string
	Args []string
	Env  []string
}

// CommandNotifier builds a platform Command per notification and runs it.
type CommandNotifier struct {
	GOOS string
	Path string // resolved helper binary
	Run  Runner
}

// Notify sanitises title and body and runs the platform helper.
func (c CommandNotifier) Notify(title, body string) error {
	cmd, err := BuildCommand(c.GOOS, c.Path, title, body)
	if err != nil {
		return err
	}
	run := c.Run
	if run == nil {
		run = ExecRunner
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	return run(ctx, cmd.Name, cmd.Args, cmd.Env)
}

// helperFor names the helper program used on goos.
func helperFor(goos string) string {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		return "notify-send"
	case "darwin":
		return "osascript"
	case "windows":
		return "powershell.exe"
	}
	return ""
}

// BuildCommand returns the helper invocation for goos; path is the helper binary (its base name
// is used when empty). Title and body are sanitised here.
func BuildCommand(goos, path, title, body string) (Command, error) {
	title, body = Clean(title, MaxLen), Clean(body, MaxLen)
	if title == "" {
		title = "nexus-cli"
	}
	if path == "" {
		path = helperFor(goos)
	}
	switch helperFor(goos) {
	case "notify-send":
		// "--" ends option parsing so a title starting with "-" is not taken as a flag; the body is
		// escaped because notification daemons may interpret it as markup.
		return Command{Name: path, Args: []string{"--app-name=nexus-cli", "-u", "critical", "--", title, markupEscape(body)}}, nil
	case "osascript":
		script := "display notification " + appleScriptString(body) + " with title " + appleScriptString(title)
		return Command{Name: path, Args: []string{"-e", script}}, nil
	case "powershell.exe":
		return Command{
			Name: path,
			Args: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-EncodedCommand", encodePowerShell(windowsScript)},
			// Untrusted text travels only in the environment; the script itself is constant.
			Env: []string{"NEXUS_NOTIFY_TITLE=" + title, "NEXUS_NOTIFY_BODY=" + body},
		}, nil
	}
	return Command{}, fmt.Errorf("notify: unsupported platform %q", goos)
}

// windowsScript shows a toast via the WinRT notification API, falling back to a tray balloon.
const windowsScript = `$ErrorActionPreference = 'Stop'
$title = $env:NEXUS_NOTIFY_TITLE
$body = $env:NEXUS_NOTIFY_BODY
try {
  [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
  $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
  $nodes = $xml.GetElementsByTagName('text')
  [void]$nodes.Item(0).AppendChild($xml.CreateTextNode($title))
  [void]$nodes.Item(1).AppendChild($xml.CreateTextNode($body))
  $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
  $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
} catch {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $n = New-Object System.Windows.Forms.NotifyIcon
  $n.Icon = [System.Drawing.SystemIcons]::Information
  $n.BalloonTipTitle = $title
  $n.BalloonTipText = $body
  $n.Visible = $true
  $n.ShowBalloonTip(10000)
  Start-Sleep -Seconds 6
  $n.Dispose()
}
`

// encodePowerShell encodes a script for -EncodedCommand (base64 of UTF-16LE).
func encodePowerShell(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i] = byte(c)
		b[2*i+1] = byte(c >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// appleScriptString quotes s as an AppleScript string literal.
func appleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func markupEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// Clean makes untrusted text safe to display: control characters (including newlines and escape
// sequences), invalid UTF-8 and bidirectional overrides become spaces, runs of whitespace collapse,
// and the result is truncated to n runes with an ellipsis.
func Clean(s string, n int) string {
	var b strings.Builder
	space := false
	for i, w := 0, 0; i < len(s); i += w {
		r, size := utf8.DecodeRuneInString(s[i:])
		w = size
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) || isBidiOrInvisible(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if n > 0 && utf8.RuneCountInString(out) > n {
		out = string([]rune(out)[:n-1]) + "…"
	}
	return out
}

func isBidiOrInvisible(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C:
		return true
	case r == 0x2028 || r == 0x2029 || r == 0xFEFF || (r >= 0x200B && r <= 0x200D):
		return true
	}
	return false
}

// Mode values accepted by New and the NEXUS_NOTIFY environment variable.
const (
	ModeAuto = "auto"
	ModeOff  = "off"
)

// ParseMode validates a --notify value.
func ParseMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeAuto, "on":
		return ModeAuto, nil
	case ModeOff, "none", "false", "0":
		return ModeOff, nil
	}
	return "", fmt.Errorf("invalid notify mode %q (want auto or off)", mode)
}

// ErrUnavailable reports that no notification helper exists on this system.
var ErrUnavailable = errors.New("notify: no desktop notification helper available")

// New returns the notifier for mode ("auto" or "off"). Auto also honours NEXUS_NOTIFY=off.
func New(mode string) (Notifier, error) {
	m, err := ParseMode(mode)
	if err != nil {
		return nil, err
	}
	if m == ModeOff {
		return Nop{}, nil
	}
	return Auto(), nil
}

// Auto returns the platform notifier, or Nop when NEXUS_NOTIFY=off, no helper is installed, or (on
// Unix desktops) there is no graphical session.
func Auto() Notifier {
	n, err := detect(runtime.GOOS, exec.LookPath, os.Getenv)
	if err != nil {
		return Nop{}
	}
	return n
}

func detect(goos string, lookPath func(string) (string, error), getenv func(string) string) (Notifier, error) {
	if m, err := ParseMode(getenv(EnvVar)); err == nil && m == ModeOff {
		return Nop{}, nil
	}
	helper := helperFor(goos)
	if helper == "" {
		return nil, ErrUnavailable
	}
	if helper == "notify-send" && getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" && getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return nil, ErrUnavailable
	}
	path, err := lookPath(helper)
	if err != nil {
		return nil, ErrUnavailable
	}
	return CommandNotifier{GOOS: goos, Path: path}, nil
}
