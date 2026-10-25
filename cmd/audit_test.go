package cmd

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

func resetAuditFlags() {
	auditPath = ""
	auditTailN, auditTailFollow, auditTailJSON, auditTailInterval = 20, false, false, audit.DefaultFollowInterval
	auditFilterAgent, auditFilterDecision, auditFilterSince = "", "", ""
	auditVerifyAnchor, auditVerifyPubKey, auditVerifyRequireSigned = "", "", false
	auditHeadJSON = false
	auditExportFormat = "jsonl"
	auditKeygenPath = ""
}

// auditOutBuffer lets a test read output while a --follow command is still writing.
type auditOutBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *auditOutBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *auditOutBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func runAuditCtx(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	resetAuditFlags()
	out := &auditOutBuffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetArgs(append([]string{"audit"}, args...))
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		resetAuditFlags()
	})
	// Cobra only propagates the context to subcommands whose ctx is still nil, so earlier
	// Execute calls in this test binary would otherwise leave a stale context behind.
	for _, c := range auditCmd.Commands() {
		c.SetContext(ctx)
	}
	err := rootCmd.ExecuteContext(ctx)
	return out.String(), err
}

func runAudit(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return runAuditCtx(t, context.Background(), args...)
}

// seedAudit creates NEXUS_HOME with a signed log of n entries alternating allow/deny and agents a/b.
func seedAudit(t *testing.T, n int) (home string, l *audit.Logger) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	kp, _ := audit.DefaultKeyPath()
	key, err := audit.LoadOrCreateKey(kp)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := audit.DefaultPath()
	l, err = audit.OpenWithOptions(path, audit.Options{SigningKey: key, Fsync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	for i := 0; i < n; i++ {
		e := audit.Entry{Agent: "a", ActAs: "alice", Tool: "GET", Target: "https://x/" + string(rune('a'+i)), Decision: "allow"}
		if i%2 == 1 {
			e.Agent, e.Decision, e.Reason = "b", "deny", "no rule, \"denied\""
		}
		if err := l.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	return home, l
}

func TestAuditHeadAndVerifyAnchor(t *testing.T) {
	home, l := seedAudit(t, 4)

	out, err := runAudit(t, "head")
	if err != nil {
		t.Fatal(err, out)
	}
	es, _ := audit.ReadAll(filepath.Join(home, "audit.jsonl"))
	head := es[3]
	if !strings.Contains(out, "seq   4") || !strings.Contains(out, "hash  "+head.Hash) || !strings.Contains(out, "time  ") {
		t.Fatalf("head output:\n%s", out)
	}
	out, err = runAudit(t, "head", "--json")
	var h struct {
		Seq  uint64 `json:"seq"`
		Hash string `json:"hash"`
	}
	if err != nil || json.Unmarshal([]byte(out), &h) != nil || h.Seq != 4 || h.Hash != head.Hash {
		t.Fatalf("head --json: %v %s", err, out)
	}

	_ = l.Log(audit.Entry{Agent: "a", Decision: "allow"})
	out, err = runAudit(t, "verify", "--anchor", head.Hash, "--require-signed")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"5 entries verified across 1 file(s)", "5 signed, 0 unsigned", "signatures verified with " + filepath.Join(home, "audit.pub"), "anchor found at seq 4"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q:\n%s", want, out)
		}
	}
	if _, err := runAudit(t, "verify", "--anchor", strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing anchor should fail: %v", err)
	}
}

func TestAuditVerifyRequireSignedAndPubkey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	path := filepath.Join(home, "audit.jsonl")
	l, _ := audit.Open(path) // unsigned
	_ = l.Log(audit.Entry{Agent: "a", Decision: "allow"})
	l.Close()

	if out, err := runAudit(t, "verify"); err != nil || !strings.Contains(out, "0 signed, 1 unsigned") {
		t.Fatalf("unsigned verify: %v %s", err, out)
	}
	if _, err := runAudit(t, "verify", "--require-signed"); err == nil || !strings.Contains(err.Error(), "signatures required") {
		t.Fatalf("--require-signed: %v", err)
	}
	if _, err := runAudit(t, "verify", "--pubkey", filepath.Join(home, "missing.pub")); err == nil {
		t.Fatal("explicit missing pubkey must error")
	}

	// Signed with one key, verified with another.
	other := filepath.Join(t.TempDir(), "other.key")
	if _, err := audit.LoadOrCreateKey(other); err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(t.TempDir(), "signed.jsonl")
	key, _ := audit.LoadOrCreateKey(filepath.Join(home, "audit.key"))
	sl, _ := audit.OpenWithOptions(signedPath, audit.Options{SigningKey: key})
	_ = sl.Log(audit.Entry{Decision: "allow"})
	sl.Close()
	if _, err := runAudit(t, "verify", "--file", signedPath, "--pubkey", audit.PublicKeyPath(other)); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("wrong pubkey: %v", err)
	}
	if out, err := runAudit(t, "verify", "--file", signedPath); err != nil || !strings.Contains(out, "signatures verified") {
		t.Fatalf("default pubkey: %v %s", err, out)
	}
}

func TestAuditVerifyTampered(t *testing.T) {
	home, l := seedAudit(t, 3)
	l.Close()
	path := filepath.Join(home, "audit.jsonl")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(b, []byte(`"decision":"deny"`), []byte(`"decision":"allow"`), 1), 0o600)
	if _, err := runAudit(t, "verify"); err == nil || !strings.Contains(err.Error(), "INVALID") {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := runAudit(t, "head"); err == nil {
		t.Fatal("head must refuse a broken chain")
	}
}

func TestAuditExport(t *testing.T) {
	seedAudit(t, 4)
	out, err := runAudit(t, "export")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "\n"); n != 4 {
		t.Fatalf("jsonl lines %d:\n%s", n, out)
	}
	out, err = runAudit(t, "export", "--decision", "deny", "--agent", "b", "--format", "csv", "--since", "1h")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(recs) != 3 {
		t.Fatalf("csv: %v %d\n%s", err, len(recs), out)
	}
	if recs[1][7] != `no rule, "denied"` || recs[1][6] != "deny" {
		t.Fatalf("csv row %q", recs[1])
	}
	if out, _ := runAudit(t, "export", "--since", "2099-01-01T00:00:00Z"); out != "" {
		t.Fatalf("future since should export nothing: %q", out)
	}
	if _, err := runAudit(t, "export", "--format", "xml"); err == nil {
		t.Fatal("bad format should error")
	}
	if _, err := runAudit(t, "export", "--decision", "maybe"); err == nil {
		t.Fatal("bad decision should error")
	}
}

func TestAuditTailFiltersAndJSON(t *testing.T) {
	seedAudit(t, 6)
	out, err := runAudit(t, "tail", "-n", "2", "--decision", "allow")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "\n") != 2 || strings.Contains(out, "deny") {
		t.Fatalf("tail filter:\n%s", out)
	}
	out, _ = runAudit(t, "tail", "--json", "--agent", "b")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("tail --json: %s", out)
	}
	var e audit.Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.Agent != "b" || e.Hash == "" {
		t.Fatal(err, lines[0])
	}
}

func TestAuditTailEmpty(t *testing.T) {
	t.Setenv("NEXUS_HOME", t.TempDir())
	if out, err := runAudit(t, "tail"); err != nil || !strings.Contains(out, "no audit entries") {
		t.Fatal(err, out)
	}
}

func TestAuditTailFollow(t *testing.T) {
	_, l := seedAudit(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	var out string
	var err error
	go func() {
		defer close(done)
		out, err = runAuditCtx(t, ctx, "tail", "-f", "--interval", "10ms", "--agent", "new")
	}()
	time.Sleep(100 * time.Millisecond)
	_ = l.Log(audit.Entry{Agent: "other", Decision: "allow"})
	_ = l.Log(audit.Entry{Agent: "new", Decision: "deny", Target: "followed-target"})
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "followed-target") || strings.Contains(out, "agent=other") {
		t.Fatalf("follow output:\n%s", out)
	}
}

func TestAuditKeygen(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	out, err := runAudit(t, "keygen")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := audit.LoadPublicKeys(filepath.Join(home, "audit.pub"))
	if err != nil || !strings.Contains(out, audit.EncodePublicKey(keys[0])) || !strings.Contains(out, audit.KeyID(keys[0])) {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	out2, _ := runAudit(t, "keygen")
	if out2 != out {
		t.Fatal("keygen must be idempotent")
	}
}
