//go:build !windows

package audit

import "os"

// openFile opens an audit log file. On Unix an open file can always be renamed or removed.
func openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}

// truncateFile shrinks the audit log at name to size bytes.
func truncateFile(name string, size int64) error { return os.Truncate(name, size) }
