package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// WebhookOptions tunes a WebhookSink. Zero values select the defaults noted per field.
type WebhookOptions struct {
	Headers        map[string]string
	QueueSize      int           // 1000; when full the oldest queued entry is dropped
	BatchSize      int           // 100 entries per POST
	MaxRetries     int           // 5 retries per batch (on network errors, 429 and 5xx)
	InitialBackoff time.Duration // 200ms, doubling
	MaxBackoff     time.Duration // 10s
	Timeout        time.Duration // 10s per request
	CloseTimeout   time.Duration // 5s to flush the queue on Close
	Client         *http.Client
}

// WebhookSink POSTs batches of entries as a JSON array from a background goroutine. Write
// never blocks.
type WebhookSink struct {
	url  string
	o    WebhookOptions
	mu   sync.Mutex
	q    []Entry
	shut bool

	wake   chan struct{}
	quit   chan struct{}
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc

	dropped, sent, failed atomic.Uint64
}

// ErrSinkClosed is returned by Write after Close.
var ErrSinkClosed = errors.New("audit sink closed")

// NewWebhookSink returns a webhook sink with default options and extra request headers.
func NewWebhookSink(rawURL string, headers map[string]string) (*WebhookSink, error) {
	return NewWebhookSinkWithOptions(rawURL, WebhookOptions{Headers: headers})
}

// NewWebhookSinkWithOptions returns a webhook sink with explicit tuning.
func NewWebhookSinkWithOptions(rawURL string, o WebhookOptions) (*WebhookSink, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("audit webhook: invalid url %q", rawURL)
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 100
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	} else if o.MaxRetries == 0 {
		o.MaxRetries = 5
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = 200 * time.Millisecond
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 10 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.CloseTimeout <= 0 {
		o.CloseTimeout = 5 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &WebhookSink{
		url: rawURL, o: o,
		wake: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{}),
		ctx: ctx, cancel: cancel,
	}
	go s.run()
	return s, nil
}

// Write enqueues e, dropping the oldest queued entry when the queue is full.
func (s *WebhookSink) Write(e Entry) error {
	s.mu.Lock()
	if s.shut {
		s.mu.Unlock()
		return ErrSinkClosed
	}
	if len(s.q) >= s.o.QueueSize {
		copy(s.q, s.q[1:])
		s.q = s.q[:len(s.q)-1]
		s.dropped.Add(1)
	}
	s.q = append(s.q, e)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

// Dropped is the number of entries discarded because the queue was full.
func (s *WebhookSink) Dropped() uint64 { return s.dropped.Load() }

// Sent is the number of entries delivered.
func (s *WebhookSink) Sent() uint64 { return s.sent.Load() }

// Failed is the number of entries abandoned after exhausting retries (or on Close timeout).
func (s *WebhookSink) Failed() uint64 { return s.failed.Load() }

// Close flushes queued entries (bounded by CloseTimeout) and stops the worker.
func (s *WebhookSink) Close() error {
	s.mu.Lock()
	if s.shut {
		s.mu.Unlock()
		return nil
	}
	s.shut = true
	s.mu.Unlock()
	close(s.quit)
	t := time.NewTimer(s.o.CloseTimeout)
	defer t.Stop()
	select {
	case <-s.done:
	case <-t.C:
		s.cancel()
		<-s.done
	}
	s.cancel()
	if n := s.pending(); n > 0 {
		return fmt.Errorf("audit webhook: %d entries not delivered", n)
	}
	return nil
}

func (s *WebhookSink) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.q)
}

func (s *WebhookSink) take() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(len(s.q), s.o.BatchSize)
	if n == 0 {
		return nil
	}
	batch := make([]Entry, n)
	copy(batch, s.q[:n])
	s.q = append(s.q[:0], s.q[n:]...)
	return batch
}

func (s *WebhookSink) run() {
	defer close(s.done)
	for {
		if s.ctx.Err() != nil {
			return
		}
		batch := s.take()
		if batch == nil {
			select {
			case <-s.wake:
				continue
			case <-s.quit:
				if s.pending() == 0 {
					return
				}
				continue
			}
		}
		s.deliver(batch)
	}
}

func (s *WebhookSink) deliver(batch []Entry) {
	body, err := json.Marshal(batch)
	if err != nil {
		s.failed.Add(uint64(len(batch)))
		return
	}
	backoff := s.o.InitialBackoff
	for attempt := 0; ; attempt++ {
		retry, err := s.post(body)
		if err == nil {
			s.sent.Add(uint64(len(batch)))
			return
		}
		if !retry || attempt >= s.o.MaxRetries {
			s.failed.Add(uint64(len(batch)))
			return
		}
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-s.ctx.Done():
			t.Stop()
			s.failed.Add(uint64(len(batch)))
			return
		}
		backoff = min(backoff*2, s.o.MaxBackoff)
	}
}

func (s *WebhookSink) post(body []byte) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nexus-cli-audit")
	for k, v := range s.o.Headers {
		req.Header.Set(k, v)
	}
	resp, err := s.o.Client.Do(req)
	if err != nil {
		return true, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return retry, fmt.Errorf("audit webhook: HTTP %d", resp.StatusCode)
}
