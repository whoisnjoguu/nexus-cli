package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/pflag"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/notify"
)

// addNotifyFlag registers --notify (auto|off) for commands that queue approvals on a broker.
func addNotifyFlag(fs *pflag.FlagSet, p *string) {
	fs.StringVar(p, "notify", notify.ModeAuto, "Desktop notifications for pending approvals: auto or off (NEXUS_NOTIFY=off also disables them)")
}

// startApprovalNotifier sends desktop notifications for new requests on broker until the returned
// stop function is called. ctl may be nil; when set, notifications point at its web UI while a UI
// session is signed in. An invalid mode is an error; a missing notification helper is not.
func startApprovalNotifier(mode string, broker *hitl.Broker, ctl *control.Server, logw io.Writer) (stop func(), err error) {
	n, err := notify.New(mode)
	if err != nil {
		return func() {}, err
	}
	if _, nop := n.(notify.Nop); nop {
		return func() {}, nil
	}
	info := notify.Info{}
	if ctl != nil {
		info.UIURL = ctl.UIPageURL()
		info.UIActive = ctl.UISessionActive
	}
	reported := false
	info.OnError = func(err error) {
		if !reported && logw != nil {
			reported = true
			fmt.Fprintf(logw, "note: desktop notification failed (further errors suppressed): %v\n", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		notify.WatchBroker(ctx, broker, n, info)
	}()
	return func() { cancel(); <-done }, nil
}
