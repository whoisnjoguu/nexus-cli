package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
)

// HealthPath mirrors proxy.HealthPath (kept local so this package stays free of the proxy).
const HealthPath = "/_nexus/health"

// State is $NEXUS_HOME/service.json, written at install so status, doctor and clients can find
// the service's proxy without parsing platform files.
type State struct {
	Name        string    `json:"name"`
	Platform    string    `json:"platform"`
	Definition  string    `json:"definition"`
	Listen      string    `json:"listen"`
	Policy      string    `json:"policy"`
	Executable  string    `json:"executable"`
	Args        []string  `json:"args"`
	NexusHome   string    `json:"nexus_home"`
	InstalledAt time.Time `json:"installed_at"`
}

// StatePath returns the state file for a service name: service.json for the default name,
// service-<name>.json otherwise.
func StatePath(nexusHome, name string) string {
	if name == "" || name == DefaultName {
		return filepath.Join(nexusHome, "service.json")
	}
	return filepath.Join(nexusHome, "service-"+name+".json")
}

// WriteState writes st to path (0600, atomically).
func WriteState(path string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFiles([]File{{Path: path, Content: string(b) + "\n", Mode: 0o600}})
}

// ReadState reads a state file written by WriteState.
func ReadState(path string) (State, error) {
	var st State
	b, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("%s: %w", path, err)
	}
	return st, nil
}

// RemoveState deletes a state file; a missing file is not an error.
func RemoveState(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

var listenRE = regexp.MustCompile(`--listen(?:</string>\s*<string>|\s+)"?([^\s"<^]+)`)

// ListenFromDefinition extracts the --listen address from a rendered unit, plist or task script.
func ListenFromDefinition(content string) string {
	if m := listenRE.FindStringSubmatch(content); m != nil {
		return m[1]
	}
	return ""
}

// Health is the result of probing the proxy's health endpoint.
type Health struct {
	OK      bool   `json:"ok"`
	URL     string `json:"url"`
	Service string `json:"service,omitempty"`
	MITM    string `json:"mitm,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ProbeAddr maps a listen address to one a local client can dial (wildcards become loopback).
func ProbeAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

// CheckHealth GETs http://<listen>/_nexus/health directly (never through an HTTP proxy).
func CheckHealth(ctx context.Context, listen string) Health {
	h := Health{URL: "http://" + ProbeAddr(listen) + HealthPath}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	hc := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		h.Error = fmt.Sprintf("HTTP %d: not a nexus health response", resp.StatusCode)
		return h
	}
	h.Service, _ = body["service"].(string)
	h.MITM, _ = body["mitm"].(string)
	switch {
	case resp.StatusCode != http.StatusOK:
		h.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	case h.Service != "nexus-cli":
		h.Error = "not a nexus-cli proxy"
	case body["status"] != "ok":
		h.Error = fmt.Sprintf("status %v", body["status"])
	default:
		h.OK = true
	}
	return h
}

// WaitHealthy polls CheckHealth until it succeeds or timeout elapses.
func WaitHealthy(ctx context.Context, listen string, timeout time.Duration) Health {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		h := CheckHealth(ctx, listen)
		if h.OK {
			return h
		}
		select {
		case <-ctx.Done():
			return h
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// MatchControl picks the discovery entry of the service's dev process: same PID, or a dev
// endpoint whose proxy listens on the service's address.
func MatchControl(infos []control.Info, listen string, pid int) *control.Info {
	for i := range infos {
		if infos[i].Kind == "dev" && pid > 0 && infos[i].PID == pid {
			return &infos[i]
		}
	}
	for i := range infos {
		if infos[i].Kind == "dev" && sameListen(infos[i].Listen, listen) {
			return &infos[i]
		}
	}
	return nil
}

func sameListen(a, b string) bool {
	if a == b {
		return true
	}
	ha, pa, err1 := net.SplitHostPort(ProbeAddr(a))
	hb, pb, err2 := net.SplitHostPort(ProbeAddr(b))
	if err1 != nil || err2 != nil || pa != pb {
		return false
	}
	return ha == hb || (IsLoopbackHost(ha) && IsLoopbackHost(hb))
}
