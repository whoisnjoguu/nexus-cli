package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recorder struct {
	mu      sync.Mutex
	batches [][]Entry
	headers []http.Header
}

func (r *recorder) add(b []Entry, h http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, b)
	r.headers = append(r.headers, h)
}

func (r *recorder) entries() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Entry
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

func decodeBatch(t *testing.T, r *http.Request) []Entry {
	body, _ := io.ReadAll(r.Body)
	var b []Entry
	if err := json.Unmarshal(body, &b); err != nil {
		t.Errorf("bad body %q: %v", body, err)
	}
	return b
}

func TestWebhookBatchingAndHeaders(t *testing.T) {
	rec := &recorder{}
	release := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-release // hold the first request so later entries accumulate into a batch
		}
		rec.add(decodeBatch(t, r), r.Header.Clone())
	}))
	defer srv.Close()

	s, err := NewWebhookSinkWithOptions(srv.URL, WebhookOptions{Headers: map[string]string{"Authorization": "Bearer t"}, BatchSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Write(Entry{Seq: 1})
	time.Sleep(50 * time.Millisecond)
	for i := 2; i <= 51; i++ {
		_ = s.Write(Entry{Seq: uint64(i)})
	}
	close(release)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	got := rec.entries()
	if len(got) != 51 || s.Sent() != 51 {
		t.Fatalf("received %d, sent %d", len(got), s.Sent())
	}
	for i, e := range got {
		if e.Seq != uint64(i+1) {
			t.Fatalf("order: %d at %d", e.Seq, i)
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.batches) != 2 || len(rec.batches[1]) != 50 {
		t.Fatalf("expected 2 batches (1, 50), got %d", len(rec.batches))
	}
	if rec.headers[0].Get("Authorization") != "Bearer t" || rec.headers[0].Get("Content-Type") != "application/json" {
		t.Fatal(rec.headers[0])
	}
}

func TestWebhookRetriesAfter500(t *testing.T) {
	rec := &recorder{}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rec.add(decodeBatch(t, r), nil)
	}))
	defer srv.Close()
	s, _ := NewWebhookSinkWithOptions(srv.URL, WebhookOptions{InitialBackoff: 5 * time.Millisecond})
	_ = s.Write(Entry{Seq: 7})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := rec.entries(); len(got) != 1 || got[0].Seq != 7 || calls.Load() != 3 {
		t.Fatalf("got %v after %d calls", got, calls.Load())
	}
	if s.Failed() != 0 {
		t.Fatal(s.Failed())
	}
}

func TestWebhookGivesUpOn4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	s, _ := NewWebhookSinkWithOptions(srv.URL, WebhookOptions{InitialBackoff: time.Millisecond})
	_ = s.Write(Entry{})
	_ = s.Close()
	if calls.Load() != 1 || s.Failed() != 1 {
		t.Fatalf("calls=%d failed=%d", calls.Load(), s.Failed())
	}
}

func TestWebhookDropsOldestWhenBlocked(t *testing.T) {
	rec := &recorder{}
	release := make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			<-release
		}
		rec.add(decodeBatch(t, r), nil)
	}))
	defer srv.Close()
	s, _ := NewWebhookSinkWithOptions(srv.URL, WebhookOptions{QueueSize: 5, BatchSize: 100})
	_ = s.Write(Entry{Seq: 1})
	time.Sleep(50 * time.Millisecond) // worker now blocked on the first POST

	start := time.Now()
	for i := 2; i <= 101; i++ {
		_ = s.Write(Entry{Seq: uint64(i)})
	}
	if time.Since(start) > time.Second {
		t.Fatal("Write must never block")
	}
	if s.Dropped() != 95 {
		t.Fatalf("dropped %d, want 95", s.Dropped())
	}
	close(release)
	_ = s.Close()
	got := rec.entries()
	if len(got) != 6 || got[0].Seq != 1 || got[1].Seq != 97 || got[5].Seq != 101 {
		t.Fatalf("expected seq 1 then newest 97..101, got %v", got)
	}
	if err := s.Write(Entry{}); err != ErrSinkClosed {
		t.Fatal(err)
	}
}

func TestWebhookCloseTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	s, _ := NewWebhookSinkWithOptions(srv.URL, WebhookOptions{CloseTimeout: 50 * time.Millisecond})
	_ = s.Write(Entry{})
	_ = s.Write(Entry{})
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	_ = s.Close()
	if time.Since(start) > 2*time.Second {
		t.Fatal("Close must be bounded")
	}
}

func TestWebhookInvalidURL(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "not a url", "http://"} {
		if _, err := NewWebhookSink(u, nil); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
}

func TestLoggerFeedsSinksAndSinkErrorsDontFailLog(t *testing.T) {
	ok := &memSink{}
	bad := &memSink{err: io.ErrClosedPipe}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWithOptions(path, Options{Sinks: []Sink{ok, bad}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(Entry{Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	es, _ := ReadAll(path)
	if len(ok.got) != 3 || ok.got[2].Hash != es[2].Hash || !ok.closed || !bad.closed {
		t.Fatalf("sink got %d entries, closed=%v", len(ok.got), ok.closed)
	}
}

type memSink struct {
	got    []Entry
	err    error
	closed bool
}

func (m *memSink) Write(e Entry) error { m.got = append(m.got, e); return m.err }
func (m *memSink) Close() error        { m.closed = true; return nil }
