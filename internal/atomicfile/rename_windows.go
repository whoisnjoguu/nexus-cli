//go:build windows

package atomicfile

import (
	"errors"
	"os"
	"syscall"
	"time"
)

const errSharingViolation syscall.Errno = 32 // ERROR_SHARING_VIOLATION

// renameTimeout bounds how long rename waits for readers to close the target.
var renameTimeout = 2 * time.Second

// rename retries while another process holds the target open: Windows refuses to replace a file
// that is open without FILE_SHARE_DELETE (which os.Open doesn't request), and readers such as
// 'nexus-cli approve' polling the discovery file only hold it for a moment.
func rename(from, to string) error {
	deadline := time.Now().Add(renameTimeout)
	delay := time.Millisecond
	for {
		err := os.Rename(from, to)
		if err == nil || !retryable(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 50*time.Millisecond {
			delay *= 2
		}
	}
}

func retryable(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED) || errors.Is(err, errSharingViolation)
}
