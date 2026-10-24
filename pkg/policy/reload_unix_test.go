//go:build unix

package policy

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestWatcherReloadsOnSIGHUP(t *testing.T) {
	w, e, path, al, _ := newTestWatcher(t, polAllowX)
	w.cfg.Interval = time.Hour // only the signal can trigger a reload
	w.Start()
	if err := os.WriteFile(path, []byte(polDenyX), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "SIGHUP reload", func() bool { return toolAction(e, "x") == ActionDeny })
	if ents := al.all(); len(ents) == 0 || ents[0].Decision != "allow" {
		t.Fatalf("audit = %+v", ents)
	}
}
