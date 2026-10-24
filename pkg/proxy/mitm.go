package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	tlsHandshakeTimeout = 10 * time.Second
	// caHintInterval rate-limits the "client rejected nexus CA" stderr hint per host.
	caHintInterval = time.Minute
)

// handleMITM intercepts a CONNECT tunnel: it terminates the client's TLS with a leaf minted by the
// local CA and serves every HTTP/1.1 request inside through the same pipeline as plain HTTP. The
// identity authenticated on the CONNECT applies to every request on the tunnel.
func (p *ProxyServer) handleMITM(w http.ResponseWriter, r *http.Request, id identity) {
	hostname, upstreamHost := splitConnectHost(r.Host)
	if hostname == "" {
		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !p.trackTunnel(clientConn) {
		_ = clientConn.Close()
		return
	}
	_ = clientConn.SetDeadline(time.Time{})

	var conn net.Conn = clientConn
	if brw != nil && brw.Reader.Buffered() > 0 {
		conn = &bufferedConn{Conn: clientConn, r: brw.Reader}
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		p.untrackTunnel(clientConn)
		return
	}

	go func() {
		defer p.untrackTunnel(clientConn)
		defer clientConn.Close()
		p.serveMITM(conn, hostname, upstreamHost, id)
	}()
}

// serveMITM performs the TLS handshake and serves HTTP/1.1 (keep-alive, chunked bodies, Upgrade)
// on the decrypted connection until the client, the upstream, or shutdown closes it.
func (p *ProxyServer) serveMITM(raw net.Conn, hostname, upstreamHost string, id identity) {
	cfg := p.cfg.MITM.ServerTLSConfig(hostname)
	mint := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" && !strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), hostname) {
			return nil, fmt.Errorf("SNI %q does not match CONNECT host %q", hello.ServerName, hostname)
		}
		return mint(hello)
	}

	tconn := tls.Server(raw, cfg)
	ctx, cancel := context.WithTimeout(p.lifetime(), tlsHandshakeTimeout)
	err := tconn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		p.handshakeFailed(hostname, upstreamHost, id, err)
		return
	}

	closed := make(chan struct{})
	nc := &notifyConn{Conn: tconn, closed: closed}
	ln := newOneShotListener(nc)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.handleInner(w, r, hostname, upstreamHost, id)
		}),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln)
	}()
	// The conn closes when keep-alive ends, the client leaves, an upgraded stream finishes, or
	// shutdown closes the underlying tunnel conn.
	<-closed
	_ = ln.Close()
	<-served
	if err := nc.rejectedBeforeRequest(); err != nil {
		p.handshakeFailed(hostname, upstreamHost, id, err)
	}
}

// handleInner gates one decrypted request from an intercepted tunnel.
func (p *ProxyServer) handleInner(w http.ResponseWriter, r *http.Request, hostname, upstreamHost string, id identity) {
	stripNexusHeaders(r)

	if h := hostOnly(r.Host); !strings.EqualFold(h, hostname) {
		reason := fmt.Sprintf("Host header %q does not match CONNECT host %q (domain fronting blocked)", r.Host, hostname)
		p.record(id.jti, id.agentID, id.actAs, r.Method, upstreamHost+r.URL.Path, id.scopes, false, reason)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, fmt.Sprintf(`{"error": "Forbidden", "message": %q}`, reason), http.StatusForbidden)
		return
	}

	r.URL.Scheme = "https"
	r.URL.Host = upstreamHost
	// The nexus token travelled on the CONNECT; an Authorization header inside the tunnel belongs
	// to the upstream API and must pass through untouched.
	inner := id
	inner.authSrc = tokenNone
	p.pipeline(w, r, inner, upstreamHost, true)
}

// handshakeFailed audits a client that refused the interception certificate and prints a
// rate-limited hint explaining how to make the client trust the nexus CA.
func (p *ProxyServer) handshakeFailed(hostname, target string, id identity, err error) {
	if p.lifetime().Err() != nil {
		return // shutting down; not the client's fault
	}
	hint := fmt.Sprintf("client rejected nexus CA for %s; run 'nexus-cli ca install' or use 'nexus-cli run'", hostname)
	p.record(id.jti, id.agentID, id.actAs, http.MethodConnect, target, id.scopes, false, hint+" ("+err.Error()+")")

	p.hintMu.Lock()
	last, seen := p.hintLast[hostname]
	now := time.Now()
	show := !seen || now.Sub(last) >= caHintInterval
	if show {
		p.hintLast[hostname] = now
	}
	p.hintMu.Unlock()
	if show {
		fmt.Fprintf(p.stderr, "[nexus] %s\n", hint)
	}
}

// splitConnectHost returns the lowercase hostname of a CONNECT authority and the upstream host to
// dial (the hostname, plus the port when it isn't 443).
func splitConnectHost(authority string) (hostname, upstream string) {
	h, port, err := net.SplitHostPort(authority)
	if err != nil {
		h, port = strings.Trim(authority, "[]"), "443"
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" {
		return "", ""
	}
	if port == "443" || port == "" {
		if strings.Contains(h, ":") {
			return h, "[" + h + "]"
		}
		return h, h
	}
	return h, net.JoinHostPort(h, port)
}

// hostOnly strips any port and IPv6 brackets from a Host header value.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.Trim(host, "[]"), ".")
}

// bufferedConn replays bytes the HTTP server had already buffered before the hijack.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// notifyConn closes its channel the first time the connection is closed.
type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}

	mu       sync.Mutex
	gotData  bool
	firstErr error // the read error that ended the conn before any request bytes arrived
}

func (c *notifyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if n > 0 {
		c.gotData = true
	} else if err != nil && !c.gotData && c.firstErr == nil {
		c.firstErr = err
	}
	c.mu.Unlock()
	return n, err
}

// rejectedBeforeRequest reports a client that aborted (TLS alert or reset) after the handshake but
// before sending a request: clients such as curl verify the certificate only once the handshake has
// completed, so their rejection never surfaces as a handshake error. A clean close is not counted.
func (c *notifyConn) rejectedBeforeRequest() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gotData || c.firstErr == nil {
		return nil
	}
	var alert tls.AlertError
	if errors.As(c.firstErr, &alert) || isConnReset(c.firstErr) {
		return c.firstErr
	}
	return nil
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

// oneShotListener hands a single connection to an http.Server, then blocks until closed.
type oneShotListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{addr: c.LocalAddr(), ch: make(chan net.Conn, 1), done: make(chan struct{})}
	l.ch <- c
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneShotListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.addr }
