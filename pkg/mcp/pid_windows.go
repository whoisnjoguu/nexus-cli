//go:build windows

package mcp

import "os"

// processAlive reports whether a process with this PID exists (FindProcess opens a handle and
// fails for unknown PIDs on Windows).
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
