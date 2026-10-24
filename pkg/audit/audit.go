// Package audit writes a tamper-evident, hash-chained (and optionally Ed25519-signed) record of
// every authorization decision. See docs/audit.md for the format and threat model.
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultMaxBytes is the active-file size at which the log is rotated when Options.MaxBytes is 0.
const DefaultMaxBytes int64 = 10 << 20

// ErrClosed is returned by Log after Close.
var ErrClosed = errors.New("audit logger closed")

// Entry is a single authorization event. Hash chains each entry to its predecessor so any
// deletion or edit of the log is detectable by re-walking the chain.
//
// Field order and omitempty tags are part of the on-disk hash format: entries written before
// the optional fields existed must keep hashing identically, so never reorder fields or drop
// omitempty from the optional ones.
type Entry struct {
	Seq      uint64    `json:"seq,omitempty"`
	Time     time.Time `json:"ts"`
	JTI      string    `json:"jti,omitempty"`
	Agent    string    `json:"agent"`
	ActAs    string    `json:"act_as"`
	Tool     string    `json:"tool"`
	Target   string    `json:"target"`
	Scopes   []string  `json:"scopes,omitempty"`
	Decision string    `json:"decision"`
	Reason   string    `json:"reason,omitempty"`
	Session  string    `json:"session,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	ArgsHash string    `json:"args_hash,omitempty"`
	Source   string    `json:"source,omitempty"`
	KeyID    string    `json:"key_id,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
	Sig      string    `json:"sig,omitempty"`
}

// HashArgs returns the hex SHA-256 of raw request params/arguments for Entry.ArgsHash, or ""
// when b is empty.
func HashArgs(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Options configures a Logger.
type Options struct {
	// SigningKey, when set, signs every entry's Hash with Ed25519 (Entry.Sig/KeyID).
	SigningKey ed25519.PrivateKey
	// Fsync forces each entry to stable storage before Log returns.
	Fsync bool
	// MaxBytes rotates the active file once it reaches this size: 0 = DefaultMaxBytes, <0 = never.
	MaxBytes int64
	// Sinks receive each entry after it has been durably written; their errors never fail Log.
	// The Logger owns them and closes them on Close.
	Sinks []Sink
}

// DefaultOptions returns the options used by Open: fsync on, default rotation, no signing.
func DefaultOptions() Options { return Options{Fsync: true} }

// Logger appends hash-chained entries to a JSONL file. It is safe for concurrent use within a
// process, and an advisory lock on "<path>.lock" keeps the chain linear across processes.
type Logger struct {
	mu     sync.Mutex
	path   string
	opts   Options
	keyID  string
	f      *os.File
	lock   *os.File
	size   int64 // active-file size after our last write (detects other writers)
	last   string
	seq    uint64
	closed bool
	// rotateAfter suppresses rotation retries after a failed rename (e.g. Windows sharing).
	rotateAfter time.Time
}

// Home returns the nexus state directory: $NEXUS_HOME, or ~/.nexus.
func Home() (string, error) {
	if h := os.Getenv("NEXUS_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus"), nil
}

// DefaultPath returns the conventional audit log location ($NEXUS_HOME or ~/.nexus)/audit.jsonl.
func DefaultPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "audit.jsonl"), nil
}

// Open prepares a logger with DefaultOptions, creating parent directories and seeding the
// chain from any existing tail.
func Open(path string) (*Logger, error) { return OpenWithOptions(path, DefaultOptions()) }

// OpenWithOptions prepares a logger with explicit options.
func OpenWithOptions(path string, opts Options) (*Logger, error) {
	if opts.SigningKey != nil && len(opts.SigningKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("audit signing key: invalid length %d", len(opts.SigningKey))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	l := &Logger{path: path, opts: opts}
	if opts.SigningKey != nil {
		l.keyID = KeyID(opts.SigningKey.Public().(ed25519.PublicKey))
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit lock: %w", err)
	}
	l.lock = lock
	if err := lockFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("lock audit log: %w", err)
	}
	defer unlockFile(lock)
	if err := l.reopen(); err != nil {
		lock.Close()
		return nil, err
	}
	if err := l.reload(); err != nil {
		l.f.Close()
		lock.Close()
		return nil, err
	}
	return l, nil
}

// Path returns the active log file path.
func (l *Logger) Path() string { return l.path }

// KeyID returns the signing key id, or "" when entries are unsigned.
func (l *Logger) KeyID() string { return l.keyID }

func (l *Logger) maxBytes() int64 {
	if l.opts.MaxBytes == 0 {
		return DefaultMaxBytes
	}
	return l.opts.MaxBytes
}

// reopen (re)opens the active file handle at l.path.
func (l *Logger) reopen() error {
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	f, err := openFile(l.path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	l.f = f
	return nil
}

// reload re-reads the chain head from disk, repairing a torn (crash-truncated) final line.
func (l *Logger) reload() error {
	fi, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	size := fi.Size()
	if size > 0 {
		end, err := completeLength(l.f, size)
		if err != nil {
			return err
		}
		if end != size {
			if err := truncateFile(l.path, end); err != nil {
				return fmt.Errorf("repair torn audit entry: %w", err)
			}
			size = end
		}
	}
	h, seq, err := chainHead(l.path)
	if err != nil {
		return err
	}
	l.last, l.seq, l.size = h, seq, size
	return nil
}

// Log computes the entry hash, links it to the previous entry, and appends it durably.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if err := lockFile(l.lock); err != nil {
		return fmt.Errorf("lock audit log: %w", err)
	}
	written, err := l.appendLocked(e)
	unlockFile(l.lock)
	if err != nil {
		return err
	}
	for _, s := range l.opts.Sinks {
		_ = s.Write(written)
	}
	return nil
}

func (l *Logger) appendLocked(e Entry) (Entry, error) {
	// Another process may have rotated, appended to, or removed the file since our last write.
	changed := false
	pfi, perr := os.Stat(l.path)
	ffi, ferr := l.f.Stat()
	if perr != nil || ferr != nil || !os.SameFile(pfi, ffi) {
		if err := l.reopen(); err != nil {
			return e, err
		}
		changed = true
	} else if ffi.Size() != l.size {
		changed = true
	}
	if changed {
		if err := l.reload(); err != nil {
			return e, err
		}
	}
	if mb := l.maxBytes(); mb > 0 && l.size >= mb && !time.Now().Before(l.rotateAfter) {
		if err := l.rotateLocked(); err != nil {
			return e, err
		}
	}

	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	sanitize(&e)
	e.Seq = l.seq + 1
	e.PrevHash = l.last
	e.KeyID = l.keyID
	e.Sig = ""
	e.Hash = hashEntry(e)
	if l.opts.SigningKey != nil {
		e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.opts.SigningKey, []byte(e.Hash)))
	}

	line, err := json.Marshal(e)
	if err != nil {
		return e, fmt.Errorf("marshal audit entry: %w", err)
	}
	line = append(line, '\n')
	n, err := l.f.Write(line)
	if err != nil {
		// Drop a partial write so the next writer doesn't append to a corrupt line.
		if n > 0 {
			_ = truncateFile(l.path, l.size)
		}
		return e, fmt.Errorf("write audit entry: %w", err)
	}
	if l.opts.Fsync {
		if err := l.f.Sync(); err != nil {
			return e, fmt.Errorf("fsync audit log: %w", err)
		}
	}
	l.size += int64(n)
	l.last = e.Hash
	l.seq = e.Seq
	return e, nil
}

// rotateLocked renames the active file to audit-<UTC>-<seq>.jsonl and starts a fresh one.
// On platforms where an open file can't be renamed (Windows with other writers), rotation is
// skipped and writing continues in the current file.
func (l *Logger) rotateLocked() error {
	name := rotatedName(l.path, time.Now().UTC(), l.seq)
	l.f.Close()
	l.f = nil
	renameErr := os.Rename(l.path, name)
	if err := l.reopen(); err != nil {
		return err
	}
	if renameErr != nil {
		l.rotateAfter = time.Now().Add(time.Minute)
		return l.reload()
	}
	if l.opts.Fsync {
		syncDir(filepath.Dir(l.path))
	}
	fi, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	l.size = fi.Size()
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}

// Close flushes and closes the log file and all sinks. Subsequent Log calls return ErrClosed.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var errs []error
	if l.f != nil {
		if l.opts.Fsync {
			errs = append(errs, l.f.Sync())
		}
		errs = append(errs, l.f.Close())
	}
	if l.lock != nil {
		errs = append(errs, l.lock.Close())
	}
	for _, s := range l.opts.Sinks {
		errs = append(errs, s.Close())
	}
	return errors.Join(errs...)
}

// hashEntry hashes the canonical entry content excluding its own Hash and Sig fields.
func hashEntry(e Entry) string {
	e.Hash = ""
	e.Sig = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sanitize makes strings valid UTF-8 so that the stored JSON round-trips to identical bytes
// (encoding/json would otherwise substitute U+FFFD differently on write vs re-marshal).
func sanitize(e *Entry) {
	for _, p := range []*string{&e.JTI, &e.Agent, &e.ActAs, &e.Tool, &e.Target, &e.Decision,
		&e.Reason, &e.Session, &e.Rule, &e.ArgsHash, &e.Source} {
		*p = strings.ToValidUTF8(*p, "\uFFFD")
	}
	if e.Scopes != nil {
		s := make([]string, len(e.Scopes))
		for i, v := range e.Scopes {
			s[i] = strings.ToValidUTF8(v, "\uFFFD")
		}
		e.Scopes = s
	}
}
