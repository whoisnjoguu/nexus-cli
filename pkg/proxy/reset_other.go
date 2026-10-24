//go:build !windows

package proxy

import (
	"errors"
	"syscall"
)

func isConnReset(err error) bool { return errors.Is(err, syscall.ECONNRESET) }
