package cmd

import (
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

func TestStartApprovalNotifier(t *testing.T) {
	if _, err := startApprovalNotifier("loud", hitl.NewBroker(time.Minute), nil, nil); err == nil {
		t.Fatal("invalid mode accepted")
	}
	stop, err := startApprovalNotifier("off", hitl.NewBroker(time.Minute), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	t.Setenv("NEXUS_NOTIFY", "off")
	stop, err = startApprovalNotifier("auto", hitl.NewBroker(time.Minute), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop()
}
