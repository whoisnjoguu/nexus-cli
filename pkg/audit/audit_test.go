package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(Entry{Agent: "a", ActAs: "u", Tool: "GET", Target: "/x", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_ = l.Log(Entry{Agent: "a", ActAs: "u", Decision: "allow"})
	_ = l.Log(Entry{Agent: "a", ActAs: "u", Decision: "deny"})

	data, _ := os.ReadFile(path)
	tampered := []byte(string(data)[:0])
	// Flip a decision in the raw log without recomputing the hash.
	tampered = append(tampered, []byte(replaceFirst(string(data), `"decision":"allow"`, `"decision":"deny"`))...)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err == nil {
		t.Fatal("expected verify to detect tampering")
	}
}

func TestChainResumesAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1, _ := Open(path)
	_ = l1.Log(Entry{Agent: "a", Decision: "allow"})
	l2, _ := Open(path)
	_ = l2.Log(Entry{Agent: "b", Decision: "deny"})
	if _, err := Verify(path); err != nil {
		t.Fatalf("chain should survive reopen: %v", err)
	}
}

func replaceFirst(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
