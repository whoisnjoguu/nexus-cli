//go:build unix

package policy

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyReload(c chan<- os.Signal) { signal.Notify(c, syscall.SIGHUP) }

func stopReloadNotify(c chan<- os.Signal) { signal.Stop(c) }
