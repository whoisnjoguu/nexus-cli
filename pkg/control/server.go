package control

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

const (
	maxBodyBytes = 4 << 10
	maxWait      = 60 * time.Second
	// VersionHeader carries the broker queue version; clients echo it as ?since= on long-polls so
	// changes between two polls are never missed.
	VersionHeader = "X-Nexus-Queue-Version"
)

// decisionNames is the strict wire vocabulary (no aliases).
var decisionNames = map[string]hitl.Decision{
	"once":    hitl.Once,
	"session": hitl.Session,
	"always":  hitl.Always,
	"deny":    hitl.Deny,
}

// ParseDecisionStrict accepts exactly once, session, always, or deny.
func ParseDecisionStrict(s string) (hitl.Decision, error) {
	d, ok := decisionNames[s]
	if !ok {
		return hitl.Deny, fmt.Errorf("invalid decision %q (want once, session, always, or deny)", s)
	}
	return d, nil
}

// Server is a running control endpoint.
type Server struct {
	info   Info
	broker *hitl.Broker
	ln     net.Listener
	srv    *http.Server
	path   string
	host   string

	closeOnce sync.Once
	closeErr  error
	serveDone chan struct{}
	closing   chan struct{} // releases long-polls on Close
}

// Start serves the control API for b on 127.0.0.1 with a fresh random token and writes the
// discovery file. PID, Addr, Token and Started are filled in; CWD defaults to the working directory.
func Start(b *hitl.Broker, info Info) (*Server, error) {
	if b == nil {
		return nil, errors.New("control: nil broker")
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	token, err := randHex(32)
	if err != nil {
		return nil, err
	}
	suffix, err := randHex(4)
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("control: listen: %w", err)
	}
	info.PID = os.Getpid()
	info.Addr = ln.Addr().String()
	info.Token = token
	info.Started = time.Now().UTC()
	if info.CWD == "" {
		info.CWD, _ = os.Getwd()
	}

	s := &Server{
		info:      info,
		broker:    b,
		ln:        ln,
		host:      info.Addr,
		serveDone: make(chan struct{}),
		closing:   make(chan struct{}),
	}
	s.srv = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      maxWait + 15*time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	path, err := writeInfoFile(dir, fmt.Sprintf("%d-%s.json", info.PID, suffix), info)
	if err != nil {
		ln.Close()
		return nil, err
	}
	s.path = path

	go func() {
		defer close(s.serveDone)
		_ = s.srv.Serve(ln)
	}()
	return s, nil
}

// writeInfoFile atomically writes info as a 0600 file inside dir (created 0700).
func writeInfoFile(dir, name string, info Info) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("control: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("control: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func(e error) (string, error) {
		tmp.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("control: write discovery file: %w", e)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		return cleanup(err)
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("control: write discovery file: %w", err)
	}
	return final, nil
}

// Info returns the endpoint description, including the token.
func (s *Server) Info() Info { return s.info }

// Path returns the discovery file path.
func (s *Server) Path() string { return s.path }

// Close stops the server and removes the discovery file. It is safe to call more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.closing)
		rmErr := os.Remove(s.path)
		if errors.Is(rmErr, os.ErrNotExist) {
			rmErr = nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := s.srv.Shutdown(ctx)
		if err != nil {
			err = s.srv.Close()
		}
		<-s.serveDone
		s.closeErr = errors.Join(err, rmErr)
	})
	return s.closeErr
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("GET /v1/approvals", s.handleList)
	mux.HandleFunc("POST /v1/approvals/{id}", s.handleDecide)
	return s.guard(mux)
}

// guard enforces the loopback-only, token-authenticated, non-browser access model.
func (s *Server) guard(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.info.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != s.host { // DNS rebinding
			writeError(w, http.StatusForbidden, "invalid host")
			return
		}
		if _, ok := r.Header["Origin"]; ok { // browsers only
			writeError(w, http.StatusForbidden, "cross-origin requests are not allowed")
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="nexus-control"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := Status{Info: s.info, Pending: len(s.broker.Pending())}
	st.Token = ""
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	wait, err := parseWait(q.Get("wait"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pending, version, changed := s.broker.Watch()
	if wait > 0 {
		since := q.Get("since")
		if since == "" || since == strconv.FormatUint(version, 10) {
			t := time.NewTimer(wait)
			select {
			case <-changed:
			case <-t.C:
			case <-r.Context().Done():
			case <-s.closing:
			}
			t.Stop()
			pending, version, _ = s.broker.Watch()
		}
	}
	w.Header().Set(VersionHeader, strconv.FormatUint(version, 10))
	writeJSON(w, http.StatusOK, pending)
}

func parseWait(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		secs, ierr := strconv.Atoi(v)
		if ierr != nil {
			return 0, fmt.Errorf("invalid wait %q", v)
		}
		d = time.Duration(secs) * time.Second
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid wait %q", v)
	}
	return min(d, maxWait), nil
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Decision string `json:"decision"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	d, err := ParseDecisionStrict(body.Decision)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.broker.Decide(r.PathValue("id"), d); err != nil {
		writeError(w, http.StatusNotFound, "unknown or already decided approval request")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
