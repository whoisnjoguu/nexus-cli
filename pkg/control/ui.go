package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

// Web UI authentication. The control API is bearer-token only for CLI clients; a browser cannot
// send that header from a link, so `nexus-cli approve --web` mints a one-time login code (bearer)
// and opens /ui#login=<code>. The page trades the code for an HttpOnly, SameSite=Strict session
// cookie plus a per-session CSRF token. Cookie-authenticated requests must also pass a Host
// allowlist (DNS rebinding), an Origin check (required for state-changing requests) and carry the
// CSRF token in the X-Nexus-CSRF header.
const (
	// LoginCodeTTL is how long a one-time login code stays valid.
	LoginCodeTTL = 60 * time.Second
	// SessionTTL is the lifetime of a web UI session.
	SessionTTL = 12 * time.Hour
	// CSRFHeader carries the per-session CSRF token on cookie-authenticated requests.
	CSRFHeader = "X-Nexus-CSRF"
	// SessionCookiePrefix prefixes the session cookie name; the control port is appended because
	// browsers do not scope cookies by port and several gateways may run side by side.
	SessionCookiePrefix = "nexus_ui_"

	authChallenge = "Bearer" + " realm=\"nexus-control\""

	maxLoginCodes = 16
	maxSessions   = 32

	// ContentSecurityPolicy is sent on every control API response.
	ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

//go:embed ui/index.html ui/app.js ui/app.css
var uiFiles embed.FS

// LoginCode is the response of POST /v1/ui/login-code.
type LoginCode struct {
	Code    string    `json:"code"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

// UISession is the response of POST /v1/ui/session.
type UISession struct {
	CSRF    string    `json:"csrf"`
	Expires time.Time `json:"expires"`
}

// UIState is the response of GET /v1/ui/state.
type UIState struct {
	Version   uint64         `json:"version"`
	Now       time.Time      `json:"now"`
	TimeoutMS int64          `json:"timeout_ms"`
	Endpoint  Info           `json:"endpoint"`
	Pending   []hitl.Request `json:"pending"`
	Recent    []hitl.Event   `json:"recent"`
}

type uiSession struct {
	csrf    string
	expires time.Time
}

type uiAuth struct {
	now func() time.Time

	mu       sync.Mutex
	codes    map[string]time.Time  // sha256(code) → expiry
	sessions map[string]*uiSession // sha256(cookie) → session
}

func newUIAuth() *uiAuth {
	return &uiAuth{now: time.Now, codes: map[string]time.Time{}, sessions: map[string]*uiSession{}}
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (a *uiAuth) pruneLocked(now time.Time) {
	for k, exp := range a.codes {
		if !now.Before(exp) {
			delete(a.codes, k)
		}
	}
	for k, s := range a.sessions {
		if !now.Before(s.expires) {
			delete(a.sessions, k)
		}
	}
}

// mintCode returns a fresh single-use login code.
func (a *uiAuth) mintCode() (string, time.Time, error) {
	code, err := randHex(16)
	if err != nil {
		return "", time.Time{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.pruneLocked(now)
	for len(a.codes) >= maxLoginCodes {
		evictOldest(a.codes, func(t time.Time) time.Time { return t })
	}
	exp := now.Add(LoginCodeTTL)
	a.codes[hashKey(code)] = exp
	return code, exp, nil
}

// redeem consumes code and opens a session, returning the cookie value and CSRF token.
func (a *uiAuth) redeem(code string) (cookie string, sess uiSession, ok bool) {
	if code == "" || len(code) > 128 {
		return "", uiSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	k := hashKey(code)
	exp, found := a.codes[k]
	delete(a.codes, k)
	if !found || !now.Before(exp) {
		return "", uiSession{}, false
	}
	cookie, err := randHex(32)
	if err != nil {
		return "", uiSession{}, false
	}
	csrf, err := randHex(32)
	if err != nil {
		return "", uiSession{}, false
	}
	a.pruneLocked(now)
	for len(a.sessions) >= maxSessions {
		evictOldest(a.sessions, func(s *uiSession) time.Time { return s.expires })
	}
	s := &uiSession{csrf: csrf, expires: now.Add(SessionTTL)}
	a.sessions[hashKey(cookie)] = s
	return cookie, *s, true
}

// session returns the live session for a cookie value.
func (a *uiAuth) session(cookie string) (uiSession, bool) {
	if cookie == "" {
		return uiSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	k := hashKey(cookie)
	s, ok := a.sessions[k]
	if !ok {
		return uiSession{}, false
	}
	if !a.now().Before(s.expires) {
		delete(a.sessions, k)
		return uiSession{}, false
	}
	return *s, true
}

func (a *uiAuth) revoke(cookie string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, hashKey(cookie))
}

func evictOldest[V any](m map[string]V, exp func(V) time.Time) {
	var oldest string
	var ot time.Time
	for k, v := range m {
		if t := exp(v); oldest == "" || t.Before(ot) {
			oldest, ot = k, t
		}
	}
	delete(m, oldest)
}

// ---- request authentication ----

type authKind int

const (
	authNone authKind = iota
	authBearer
	authCookie
)

type authCtxKey struct{}

type authInfo struct {
	kind   authKind
	cookie string
}

func withAuth(ctx context.Context, a authInfo) context.Context {
	return context.WithValue(ctx, authCtxKey{}, a)
}

func authFrom(ctx context.Context) authInfo {
	a, _ := ctx.Value(authCtxKey{}).(authInfo)
	return a
}

// decidedBy labels decisions in broker events by the kind of client that made them.
func decidedBy(ctx context.Context) string {
	if authFrom(ctx).kind == authCookie {
		return "web"
	}
	return "cli"
}

// publicUIRoutes are reachable without credentials (still Host-checked; the session exchange is
// also Origin-checked and validates its one-time code).
var publicUIRoutes = map[string]bool{
	"GET /ui":             true,
	"GET /ui/app.js":      true,
	"GET /ui/app.css":     true,
	"POST /v1/ui/session": true,
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
}

func (s *Server) port() string {
	_, p, _ := net.SplitHostPort(s.host)
	return p
}

func (s *Server) cookieName() string { return SessionCookiePrefix + s.port() }

// uiHostOK accepts only the loopback names the UI is served under (DNS rebinding defence).
func (s *Server) uiHostOK(host string) bool {
	p := s.port()
	return host == "127.0.0.1:"+p || host == "localhost:"+p
}

func (s *Server) uiOriginOK(origin string) bool {
	p := s.port()
	return origin == "http://127.0.0.1:"+p || origin == "http://localhost:"+p
}

// guardBrowser authenticates requests without an Authorization header: public UI assets, the
// session exchange, and cookie sessions (Host + Origin + CSRF).
func (s *Server) guardBrowser(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if !s.uiHostOK(r.Host) {
		writeError(w, http.StatusForbidden, "invalid host")
		return
	}
	origin, hasOrigin := r.Header["Origin"]
	if hasOrigin && (len(origin) != 1 || !s.uiOriginOK(origin[0])) {
		writeError(w, http.StatusForbidden, "cross-origin requests are not allowed")
		return
	}
	safe := r.Method == http.MethodGet || r.Method == http.MethodHead
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	if publicUIRoutes[method+" "+r.URL.Path] {
		if !safe && !hasOrigin {
			writeError(w, http.StatusForbidden, "missing Origin header")
			return
		}
		next.ServeHTTP(w, r)
		return
	}

	c, err := r.Cookie(s.cookieName())
	if err != nil {
		w.Header().Set("WWW-Authenticate", authChallenge)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	sess, ok := s.ui.session(c.Value)
	if !ok {
		w.Header().Set("WWW-Authenticate", authChallenge)
		writeError(w, http.StatusUnauthorized, "session expired")
		return
	}
	if !safe && !hasOrigin {
		writeError(w, http.StatusForbidden, "missing Origin header")
		return
	}
	token := r.Header.Get(CSRFHeader)
	if token == "" && r.Method == http.MethodGet && r.URL.Path == "/v1/events" {
		// EventSource cannot set request headers.
		token = r.URL.Query().Get("csrf")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(sess.csrf)) != 1 {
		writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
		return
	}
	next.ServeHTTP(w, r.WithContext(withAuth(r.Context(), authInfo{kind: authCookie, cookie: c.Value})))
}

// ---- handlers ----

func (s *Server) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui", s.serveUIFile("ui/index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /ui/app.js", s.serveUIFile("ui/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /ui/app.css", s.serveUIFile("ui/app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("POST /v1/ui/login-code", s.handleLoginCode)
	mux.HandleFunc("POST /v1/ui/session", s.handleSession)
	mux.HandleFunc("POST /v1/ui/logout", s.handleLogout)
	mux.HandleFunc("GET /v1/ui/state", s.handleUIState)
	mux.HandleFunc("GET /v1/events", s.handleEvents)
}

func (s *Server) serveUIFile(name, ctype string) http.HandlerFunc {
	data, err := fs.ReadFile(uiFiles, name)
	if err != nil {
		panic("control: missing embedded " + name)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(data)
		}
	}
}

// UIURL is the browser URL for a login code on the endpoint at addr.
func UIURL(addr, code string) string { return "http://" + addr + "/ui#login=" + code }

func (s *Server) handleLoginCode(w http.ResponseWriter, r *http.Request) {
	if authFrom(r.Context()).kind != authBearer {
		writeError(w, http.StatusForbidden, "login codes require the bearer token")
		return
	}
	code, exp, err := s.ui.mintCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint login code")
		return
	}
	writeJSON(w, http.StatusOK, LoginCode{Code: code, URL: UIURL(s.host, code), Expires: exp.UTC()})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cookie, sess, ok := s.ui.redeem(body.Code)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid, expired, or already used login code")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    cookie,
		Path:     "/",
		MaxAge:   int(SessionTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, UISession{CSRF: sess.csrf, Expires: sess.expires.UTC()})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if a := authFrom(r.Context()); a.kind == authCookie {
		s.ui.revoke(a.cookie)
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) uiState() UIState {
	pending, version, _ := s.broker.Watch()
	info := s.info
	info.Token = ""
	return UIState{
		Version:   version,
		Now:       time.Now().UTC(),
		TimeoutMS: s.broker.Timeout().Milliseconds(),
		Endpoint:  info,
		Pending:   pending,
		Recent:    s.broker.Recent(),
	}
}

// handleUIState returns the pending queue plus recent decisions; ?wait= and ?since= long-poll
// exactly like GET /v1/approvals (the fallback when SSE is unavailable).
func (s *Server) handleUIState(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	wait, err := parseWait(q.Get("wait"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if wait > 0 {
		_, version, changed := s.broker.Watch()
		if since := q.Get("since"); since == "" || since == strconv.FormatUint(version, 10) {
			t := time.NewTimer(wait)
			select {
			case <-changed:
			case <-t.C:
			case <-r.Context().Done():
			case <-s.closing:
			}
			t.Stop()
		}
	}
	st := s.uiState()
	w.Header().Set(VersionHeader, strconv.FormatUint(st.Version, 10))
	writeJSON(w, http.StatusOK, st)
}

// sseKeepalive is how often an idle event stream gets a comment line (and a session re-check).
var sseKeepalive = 15 * time.Second

// handleEvents streams broker events as Server-Sent Events: "hello" (with the queue version) on
// connect, then "added", "decided", "expired" and "cancelled", each carrying a hitl.Event.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // streams outlive the server's WriteTimeout
	events, unsubscribe := s.broker.Subscribe()
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, version, _ := s.broker.Watch()
	if err := writeSSE(w, "hello", map[string]uint64{"version": version}); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}

	a := authFrom(r.Context())
	ticker := time.NewTicker(sseKeepalive)
	defer ticker.Stop()
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return // fell behind; the client reconnects and resyncs
			}
			if writeSSE(w, string(ev.Type), ev) != nil || rc.Flush() != nil {
				return
			}
		case <-ticker.C:
			if a.kind == authCookie {
				if _, ok := s.ui.session(a.cookie); !ok {
					return
				}
			}
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil || rc.Flush() != nil {
				return
			}
		case <-r.Context().Done():
			return
		case <-s.closing:
			return
		}
	}
}

func writeSSE(w http.ResponseWriter, event string, v any) error {
	data, err := json.Marshal(v) // single line: JSON escapes newlines
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(event)+len(data)+16)
	buf = append(buf, "event: "...)
	buf = append(buf, event...)
	buf = append(buf, "\ndata: "...)
	buf = append(buf, data...)
	buf = append(buf, "\n\n"...)
	_, err = w.Write(buf)
	return err
}
