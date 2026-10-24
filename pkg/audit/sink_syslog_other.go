//go:build !unix

package audit

import (
	"fmt"
	"runtime"
)

// NewSyslogSink is unsupported on this platform.
func NewSyslogSink(network, addr, tag string) (Sink, error) {
	return nil, fmt.Errorf("audit syslog sink unsupported on %s", runtime.GOOS)
}
