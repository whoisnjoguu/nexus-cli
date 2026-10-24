package audit

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRotationContinuesChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	priv := testKey(t)
	l, err := OpenWithOptions(path, Options{SigningKey: priv, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := l.Log(Entry{Agent: "a", Target: fmt.Sprintf("/t/%d", i), Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	files, err := Files(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 || files[len(files)-1] != path {
		t.Fatalf("expected rotated set + active, got %v", files)
	}
	re := regexp.MustCompile(`^audit-\d{8}T\d{6}Z-\d+\.jsonl$`)
	var prevLast string
	for _, f := range files {
		if f != path && !re.MatchString(filepath.Base(f)) {
			t.Fatalf("bad rotated name %s", f)
		}
		es, _ := readFileEntries(f)
		if len(es) == 0 {
			t.Fatalf("empty file %s", f)
		}
		if es[0].PrevHash != prevLast {
			t.Fatalf("%s: first prev_hash doesn't link to previous file", f)
		}
		prevLast = es[len(es)-1].Hash
		if want := fmt.Sprintf("-%d.jsonl", es[len(es)-1].Seq); f != path && !strings.HasSuffix(f, want) {
			t.Fatalf("%s should end with last seq %s", f, want)
		}
		if fi, _ := os.Stat(f); f != path && fi.Size() > 1024+512 {
			t.Fatalf("%s too large: %d", f, fi.Size())
		}
	}

	res, err := VerifyWithOptions(path, VerifyOptions{PublicKeys: []ed25519.PublicKey{pubOf(priv)}, RequireSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 40 || res.HeadSeq != 40 || res.Files != len(files) {
		t.Fatalf("%+v", res)
	}

	tail, err := Tail(path, 15)
	if err != nil || len(tail) != 15 || tail[0].Seq != 26 || tail[14].Seq != 40 {
		t.Fatalf("tail across rotation: %d %v", len(tail), err)
	}
	all, _ := Tail(path, 0)
	if len(all) != 40 {
		t.Fatal(len(all))
	}
	head, _ := Head(path)
	if head.Seq != 40 {
		t.Fatal(head.Seq)
	}

	// Reopen continues seq and chain across the rotated set.
	l, _ = OpenWithOptions(path, Options{SigningKey: priv, MaxBytes: 1024})
	_ = l.Log(Entry{Agent: "b", Decision: "deny"})
	l.Close()
	if res, err := Verify(path); err != nil || res != 41 {
		t.Fatalf("after reopen: %d %v", res, err)
	}

	// Removing a rotated file breaks the chain.
	if err := os.Remove(files[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err == nil {
		t.Fatal("missing rotated file must be detected")
	}
}

func TestRotatedOrderingBySeq(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	for _, n := range []string{"audit-20260101T000000Z-100.jsonl", "audit-20260101T000000Z-9.jsonl", "audit-x.jsonl", "other-20260101T000000Z-1.jsonl"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	files, _ := Files(path)
	if len(files) != 2 || filepath.Base(files[0]) != "audit-20260101T000000Z-9.jsonl" {
		t.Fatalf("%v", files)
	}
}

func TestRotationDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := OpenWithOptions(path, Options{MaxBytes: -1})
	for i := 0; i < 20; i++ {
		_ = l.Log(Entry{Decision: "allow", Reason: "padding padding padding padding"})
	}
	l.Close()
	if files, _ := Files(path); len(files) != 1 {
		t.Fatal(files)
	}
}

func TestFollowPicksUpNewLinesAcrossRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWithOptions(path, Options{MaxBytes: 600})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = l.Log(Entry{Agent: "before", Decision: "allow"})
	head, _ := Head(path)

	var mu sync.Mutex
	var got []Entry
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, head.Hash, 10*time.Millisecond, func(e Entry) error {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
			return nil
		})
	}()
	time.Sleep(30 * time.Millisecond)
	const n = 25
	for i := 0; i < n; i++ {
		if err := l.Log(Entry{Agent: fmt.Sprintf("a%d", i), Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
		if i%5 == 0 {
			time.Sleep(15 * time.Millisecond)
		}
	}
	if files, _ := Files(path); len(files) < 3 {
		t.Fatalf("test should rotate, files=%v", files)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		c := len(got)
		mu.Unlock()
		if c >= n || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("followed %d entries, want %d", len(got), n)
	}
	for i, e := range got {
		if e.Agent != fmt.Sprintf("a%d", i) {
			t.Fatalf("entry %d = %s (duplicate or out of order)", i, e.Agent)
		}
	}
}

func TestFollowFromStartAndCallbackError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_ = l.Log(Entry{Agent: "x", Decision: "allow"})
	_ = l.Log(Entry{Agent: "y", Decision: "allow"})
	l.Close()
	stop := fmt.Errorf("stop")
	var seen []string
	err := Follow(context.Background(), path, "", time.Millisecond, func(e Entry) error {
		seen = append(seen, e.Agent)
		if len(seen) == 2 {
			return stop
		}
		return nil
	})
	if err != stop || len(seen) != 2 {
		t.Fatal(err, seen)
	}
}
