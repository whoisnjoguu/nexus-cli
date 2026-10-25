package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func FuzzExtractToken(f *testing.F) {
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	f.Add("Bearer abc.def.ghi", "", "")
	f.Add("bearer   tok  ", "Bearer other", "x")
	f.Add(basic("agent", "tok"), "", "")
	f.Add(basic("agent", "  "), "Bearer fallback", "")
	f.Add(basic("", ""), "", "nexus")
	f.Add("Basic !!!notbase64", "Basic "+base64.StdEncoding.EncodeToString([]byte("u:p")), "")
	f.Add("Basic "+base64.StdEncoding.EncodeToString([]byte("no-colon")), "", "")
	f.Add("Bearer", "Bearer ", " ")
	f.Add("Digest x", "BEARER Tok", "")
	f.Fuzz(func(t *testing.T, proxyAuth, auth, xNexus string) {
		r := &http.Request{Header: http.Header{}}
		if proxyAuth != "" {
			r.Header["Proxy-Authorization"] = []string{proxyAuth}
		}
		if auth != "" {
			r.Header["Authorization"] = []string{auth}
		}
		if xNexus != "" {
			r.Header["X-Nexus-Token"] = []string{xNexus}
		}
		tok, src := extractToken(r)
		if bearerToken(r) != tok {
			t.Fatal("bearerToken disagrees with extractToken")
		}
		if (tok == "") != (src == tokenNone) {
			t.Fatalf("token %q from source %d", tok, src)
		}
		if tok != strings.TrimSpace(tok) {
			t.Fatalf("token %q is not trimmed", tok)
		}
		switch src {
		case tokenProxyAuthorization:
			if b := schemeValue(proxyAuth, "bearer"); b != "" {
				if tok != b {
					t.Fatalf("bearer proxy auth %q gave %q", proxyAuth, tok)
				}
			} else {
				raw, err := base64.StdEncoding.DecodeString(schemeValue(proxyAuth, "basic"))
				_, pass, ok := strings.Cut(string(raw), ":")
				if err != nil || !ok || strings.TrimSpace(pass) != tok {
					t.Fatalf("basic proxy auth %q gave %q", proxyAuth, tok)
				}
			}
		case tokenAuthorization:
			// Authorization: Basic belongs to the upstream and is never taken as a nexus token.
			if schemeValue(auth, "bearer") != tok {
				t.Fatalf("Authorization %q gave %q", auth, tok)
			}
		case tokenXNexus:
			if tok != strings.TrimSpace(xNexus) {
				t.Fatalf("X-Nexus-Token %q gave %q", xNexus, tok)
			}
		}
	})
}

func FuzzSplitConnectHost(f *testing.F) {
	for _, s := range []string{
		"example.com:443", "Example.COM.:443", "example.com:8443", "[::1]:443", "[::1]:8443", "::1",
		"example.com", "[fe80::1%25en0]:443", ":443", "[]:443", "a:b:c", "evil.com.:443", ".:443", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, authority string) {
		hostname, upstream := splitConnectHost(authority)
		if hostname == "" {
			if upstream != "" {
				t.Fatalf("no hostname but upstream %q", upstream)
			}
			return
		}
		// Names with an empty label ("a..") are not valid DNS names (the dialer refuses them), so
		// only the no-panic property applies to them.
		if strings.Contains(authority, "..") {
			return
		}
		if strings.HasSuffix(hostname, ".") || hostname != strings.ToLower(hostname) {
			t.Fatalf("hostname %q is not normalized", hostname)
		}
		if !strings.ContainsAny(hostname, "[]") && !strings.EqualFold(hostOnly(upstream), strings.TrimSuffix(hostname, ".")) {
			t.Fatalf("upstream %q does not address hostname %q", upstream, hostname)
		}
		h, port, err := net.SplitHostPort(authority)
		if err != nil || h == "" || strings.Contains(h, ":") {
			return
		}
		if port != "443" && port != "" {
			if uh, up, err := net.SplitHostPort(upstream); err != nil || up != port || uh != hostname {
				t.Fatalf("upstream %q lost port %q of %q", upstream, port, authority)
			}
		}
		// Intercepted requests are evaluated against upstream, raw tunnels against the CONNECT
		// authority: both must hit the same host rules.
		pats := []string{hostname, strings.ToUpper(hostname), hostname + "."}
		if i := strings.Index(hostname, "."); i > 0 {
			pats = append(pats, "*"+hostname[i:])
		}
		for _, p := range pats {
			if policy.HostMatches([]string{p}, upstream) != policy.HostMatches([]string{p}, authority) {
				t.Fatalf("pattern %q: upstream %q and authority %q disagree", p, upstream, authority)
			}
		}
	})
}

func FuzzSameHostPort(f *testing.F) {
	f.Add("127.0.0.1:8075", "localhost:8075")
	f.Add("[::1]:8075", "0.0.0.0:8075")
	f.Add("example.com:80", "EXAMPLE.com:80")
	f.Add("a:1", "a:2")
	f.Add("garbage", "")
	f.Fuzz(func(t *testing.T, a, b string) {
		if sameHostPort(a, b) != sameHostPort(b, a) {
			t.Fatalf("sameHostPort(%q,%q) is not symmetric", a, b)
		}
		if _, _, err := net.SplitHostPort(a); err == nil && !sameHostPort(a, a) {
			t.Fatalf("sameHostPort(%q,%q) is not reflexive", a, a)
		}
	})
}

// FuzzUnauthenticatedRequests feeds arbitrary request lines and auth headers to a proxy that
// requires auth: nothing without a valid token may be forwarded, tunnelled or allowed.
func FuzzUnauthenticatedRequests(f *testing.F) {
	signer, err := jwt.NewTokenSigner()
	if err != nil {
		f.Fatal(err)
	}
	other, _ := jwt.NewTokenSigner()
	forged, _ := other.Mint(jwt.MintOptions{AgentID: "a", UserID: "u", TTL: time.Hour})
	upstreamHit := make(chan struct{}, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamHit <- struct{}{}:
		default:
		}
	}))
	f.Cleanup(up.Close)
	engine := policy.NewEngine(policy.Policy{DefaultAction: policy.ActionAllow})
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: engine, Replay: jwt.NewReplayGuard()})

	upHost := strings.TrimPrefix(up.URL, "http://")
	f.Add("GET", "http://"+upHost+"/x", upHost, "Bearer "+forged)
	f.Add("CONNECT", upHost, upHost, "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:"+forged)))
	f.Add("GET", "/_nexus/health", "", "Bearer x")
	f.Add("POST", "http://"+upHost+"/", "evil.com", "")
	f.Add("CONNECT", "evil.com.:443", "", "Bearer eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, method, target, host, proxyAuth string) {
		raw := method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\n"
		if proxyAuth != "" {
			raw += "Proxy-Authorization: " + proxyAuth + "\r\n"
		}
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw + "\r\n")))
		if err != nil {
			return
		}
		rec := httptest.NewRecorder()
		p.handleIntercept(rec, req)
		select {
		case <-upstreamHit:
			t.Fatalf("unauthenticated request reached the upstream: %q", raw)
		default:
		}
		res := rec.Result()
		body, _ := io.ReadAll(res.Body)
		if req.Method == http.MethodGet && !req.URL.IsAbs() && req.URL.Path == HealthPath {
			if strings.Contains(string(body), `"valid"`) {
				t.Fatalf("health reported a forged token as valid: %s", body)
			}
			return
		}
		if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("unauthenticated %q answered %d: %s", raw, res.StatusCode, body)
		}
	})
}
