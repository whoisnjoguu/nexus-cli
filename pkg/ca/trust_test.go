package ca

import (
	"reflect"
	"strings"
	"testing"
)

func TestTrustCommands(t *testing.T) {
	const cert = "/home/u/.nexus/ca/ca.crt"
	debian := func(p string) bool { return p == "/usr/local/share/ca-certificates" }
	rhel := func(string) bool { return false }
	cases := []struct {
		name      string
		goos      string
		exists    func(string) bool
		install   [][]string
		uninstall [][]string
	}{
		{"debian", "linux", debian,
			[][]string{{"sudo", "cp", cert, "/usr/local/share/ca-certificates/nexus-cli-ca.crt"}, {"sudo", "update-ca-certificates"}},
			[][]string{{"sudo", "rm", "-f", "/usr/local/share/ca-certificates/nexus-cli-ca.crt"}, {"sudo", "update-ca-certificates", "--fresh"}}},
		{"rhel", "linux", rhel,
			[][]string{{"sudo", "cp", cert, "/etc/pki/ca-trust/source/anchors/nexus-cli-ca.crt"}, {"sudo", "update-ca-trust"}},
			[][]string{{"sudo", "rm", "-f", "/etc/pki/ca-trust/source/anchors/nexus-cli-ca.crt"}, {"sudo", "update-ca-trust"}}},
		{"windows", "windows", rhel,
			[][]string{{"certutil", "-user", "-addstore", "Root", cert}},
			[][]string{{"certutil", "-user", "-delstore", "Root", "nexus-cli local CA"}}},
		{"plan9", "plan9", rhel, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := installCommands(tc.goos, cert, tc.exists); !reflect.DeepEqual(got, tc.install) {
				t.Errorf("install = %v, want %v", got, tc.install)
			}
			if got := uninstallCommands(tc.goos, cert, tc.exists); !reflect.DeepEqual(got, tc.uninstall) {
				t.Errorf("uninstall = %v, want %v", got, tc.uninstall)
			}
		})
	}

	t.Run("darwin", func(t *testing.T) {
		t.Setenv("HOME", "/Users/u")
		in := InstallCommands("darwin", cert)
		if len(in) != 1 || !reflect.DeepEqual(in[0][:5], []string{"security", "add-trusted-cert", "-r", "trustRoot", "-k"}) ||
			!strings.HasSuffix(in[0][5], "/Users/u/Library/Keychains/login.keychain-db") || in[0][6] != cert {
			t.Fatalf("darwin install = %v", in)
		}
		un := UninstallCommands("darwin", cert)
		if len(un) != 1 || !reflect.DeepEqual(un[0][:4], []string{"security", "delete-certificate", "-c", "nexus-cli local CA"}) {
			t.Fatalf("darwin uninstall = %v", un)
		}
	})
}
