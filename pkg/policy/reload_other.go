//go:build !unix

package policy

import "os"

// No SIGHUP outside unix: reloads happen by polling only.
func notifyReload(chan<- os.Signal) {}

func stopReloadNotify(chan<- os.Signal) {}
