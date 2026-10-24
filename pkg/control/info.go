// Package control exposes a local, token-protected HTTP API on the loopback interface so that
// another terminal (`nexus-cli approve`) can list and decide pending human-in-the-loop approvals
// of a running nexus-cli process. Each running endpoint advertises itself with a 0600 JSON file in
// Dir().
package control

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Info describes a running control endpoint; it is the content of the discovery file.
type Info struct {
	PID     int       `json:"pid"`
	Addr    string    `json:"addr"`            // host:port of the control API (always 127.0.0.1)
	Token   string    `json:"token,omitempty"` // bearer token; omitted from /v1/status
	Kind    string    `json:"kind"`            // dev | run | mcp
	Started time.Time `json:"started"`
	Listen  string    `json:"listen,omitempty"` // the proxy's own listen address
	Policy  string    `json:"policy,omitempty"`
	CWD     string    `json:"cwd,omitempty"`
}

// Status is the response of GET /v1/status.
type Status struct {
	Info
	Pending int `json:"pending"`
}

// Dir returns the discovery directory: $NEXUS_HOME/control, or ~/.nexus/control.
func Dir() (string, error) {
	if h := os.Getenv("NEXUS_HOME"); h != "" {
		return filepath.Join(h, "control"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if home == "" {
		return "", errors.New("control: cannot determine home directory")
	}
	return filepath.Join(home, ".nexus", "control"), nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
