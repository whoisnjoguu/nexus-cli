//go:build windows

package proxy

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isConnReset reports a peer reset. Winsock reports it as WSAECONNRESET (or WSAECONNABORTED
// when the local stack aborts the connection), never syscall.ECONNRESET.
func isConnReset(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED)
}
