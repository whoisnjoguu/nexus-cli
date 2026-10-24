//go:build unix

package audit

import (
	"os"
	"testing"
)

// shortTempDir avoids the ~104-byte unix socket path limit that t.TempDir() can exceed.
func shortTempDir(t *testing.T) (string, error) {
	d, err := os.MkdirTemp(".", "sock")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d, nil
}
