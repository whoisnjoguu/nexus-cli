//go:build unix

package audit

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSyslogSinkUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no udp:", err)
	}
	defer pc.Close()
	s, err := NewSyslogSink("udp", pc.LocalAddr().String(), "nexus-test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Write(Entry{Seq: 3, Agent: "agent-x", Decision: "deny", Hash: "abc"}); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	// <36> = facility AUTH(4)*8 + severity WARNING(4) for deny.
	for _, want := range []string{"<36>", "nexus-test", `"agent":"agent-x"`, `"seq":3`} {
		if !strings.Contains(msg, want) {
			t.Errorf("syslog message missing %q: %s", want, msg)
		}
	}
}

func TestSyslogSinkUnixgram(t *testing.T) {
	dir, err := shortTempDir(t)
	if err != nil {
		t.Skip(err)
	}
	sock := dir + "/s"
	pc, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skip("no unixgram:", err)
	}
	defer pc.Close()
	s, err := NewSyslogSink("unixgram", sock, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_ = s.Write(Entry{Decision: "allow"})
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if msg := string(buf[:n]); !strings.Contains(msg, "<38>") || !strings.Contains(msg, "nexus-audit") {
		t.Fatalf("unexpected message %s", msg)
	}
}
