package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// Host deny rules must hold for every spelling of the host that dials the same address: a
// trailing root dot or an IPv4-mapped IPv6 literal used to slip past them (found by fuzzing).
func TestHostDenyRuleHoldsForEquivalentSpellings(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	reached := make(chan struct{}, 16)
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			reached <- struct{}{}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())

	eng := policy.NewEngine(policy.Policy{DefaultAction: policy.ActionAllow, Tools: []policy.Rule{
		{Match: policy.Match{Host: "127.0.0.1"}, Action: policy.ActionDeny},
		{Match: policy.Match{Host: "localhost"}, Action: policy.ActionDeny},
	}})
	u, stop := startProxy(t, New(Config{Engine: eng}))
	defer stop()

	for _, host := range []string{"127.0.0.1", "[::ffff:127.0.0.1]", "localhost.", "LOCALHOST"} {
		target := net.JoinHostPort(host, port)
		if host[0] == '[' {
			target = host + ":" + port
		}
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		conn.Close()
		if err != nil {
			t.Fatalf("CONNECT %s: %v", target, err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("CONNECT %s = %d, want 403", target, resp.StatusCode)
		}

		c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}}
		resp, err = c.Get((&url.URL{Scheme: "http", Host: target, Path: "/"}).String())
		if err != nil {
			t.Fatalf("GET via %s: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET http://%s/ = %d, want 403", target, resp.StatusCode)
		}
	}
	select {
	case <-reached:
		t.Error("a denied host was dialed")
	default:
	}
}
