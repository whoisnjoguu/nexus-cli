//go:build unix

package audit

import (
	"encoding/json"
	"fmt"
	"log/syslog"
)

type syslogSink struct{ w *syslog.Writer }

// NewSyslogSink sends each entry as a JSON message to syslog (facility AUTH). An empty network
// and addr use the local syslog daemon; otherwise e.g. ("udp", "logs.example:514").
func NewSyslogSink(network, addr, tag string) (Sink, error) {
	if tag == "" {
		tag = "nexus-audit"
	}
	w, err := syslog.Dial(network, addr, syslog.LOG_AUTH|syslog.LOG_INFO, tag)
	if err != nil {
		return nil, fmt.Errorf("audit syslog: %w", err)
	}
	return &syslogSink{w: w}, nil
}

func (s *syslogSink) Write(e Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if e.Decision == "deny" {
		return s.w.Warning(string(b))
	}
	return s.w.Info(string(b))
}

func (s *syslogSink) Close() error { return s.w.Close() }
