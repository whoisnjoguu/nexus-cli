// Package audit writes a tamper-evident, hash-chained record of every authorization decision.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is a single authorization event. Hash chains each entry to its predecessor so any
// deletion or edit of the log is detectable by re-walking the chain.
type Entry struct {
	Time     time.Time `json:"ts"`
	JTI      string    `json:"jti,omitempty"`
	Agent    string    `json:"agent"`
	ActAs    string    `json:"act_as"`
	Tool     string    `json:"tool"`
	Target   string    `json:"target"`
	Scopes   []string  `json:"scopes,omitempty"`
	Decision string    `json:"decision"`
	Reason   string    `json:"reason,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Logger appends hash-chained entries to a JSONL file. It is safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	path string
	last string
}

// DefaultPath returns the conventional audit log location (~/.nexus/audit.jsonl).
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus", "audit.jsonl"), nil
}

// Open prepares a logger, creating parent directories and seeding the chain from any existing tail.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	last, err := lastHash(path)
	if err != nil {
		return nil, err
	}
	return &Logger{path: path, last: last}, nil
}

// Log computes the entry hash, links it to the previous entry, and appends it durably.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.PrevHash = l.last
	e.Hash = hashEntry(e)

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	l.last = e.Hash
	return nil
}

// hashEntry hashes the canonical entry content excluding its own Hash field.
func hashEntry(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func lastHash(path string) (string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return "", fmt.Errorf("corrupt audit entry: %w", err)
		}
		last = e.Hash
	}
	return last, sc.Err()
}

// Verify re-walks the chain, confirming each entry's hash and its link to the previous entry.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	prev := ""
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return n, fmt.Errorf("entry %d: invalid json: %w", n+1, err)
		}
		if e.PrevHash != prev {
			return n, fmt.Errorf("entry %d: broken chain (prev_hash mismatch)", n+1)
		}
		if got := hashEntry(e); got != e.Hash {
			return n, fmt.Errorf("entry %d: hash mismatch (tampered)", n+1)
		}
		prev = e.Hash
		n++
	}
	return n, sc.Err()
}

// Tail returns the last n entries in chronological order.
func Tail(path string, n int) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	var all []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("corrupt audit entry: %w", err)
		}
		all = append(all, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}
