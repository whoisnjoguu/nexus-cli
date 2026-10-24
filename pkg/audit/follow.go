package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// DefaultFollowInterval is the polling period used by Follow when interval <= 0.
const DefaultFollowInterval = 500 * time.Millisecond

// Follow polls the log (including across rotation) and calls fn for every entry appended after
// the entry whose hash is afterHash ("" = from the beginning). It returns nil when ctx is done,
// or the first error from fn or from reading the log.
func Follow(ctx context.Context, path, afterHash string, interval time.Duration, fn func(Entry) error) error {
	if interval <= 0 {
		interval = DefaultFollowInterval
	}
	st := &follower{path: path, last: afterHash, rescan: true}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := st.poll(fn); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

type follower struct {
	path   string
	last   string
	fi     os.FileInfo // active file identity as of the last read
	off    int64       // bytes of the active file already consumed
	rescan bool
}

func (s *follower) poll(fn func(Entry) error) error {
	fi, err := os.Stat(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat audit log: %w", err)
	}
	switch {
	case s.rescan:
	case fi == nil || s.fi == nil || !os.SameFile(fi, s.fi) || fi.Size() < s.off:
		s.rescan = true
	case fi.Size() == s.off:
		return nil
	}
	if s.rescan {
		return s.scan(fn)
	}
	return s.incremental(fn)
}

// scan re-reads the whole rotated set + active file and emits entries after s.last.
func (s *follower) scan(fn func(Entry) error) error {
	for attempt := 0; ; attempt++ {
		before, err := Files(s.path)
		if err != nil {
			return err
		}
		var all []Entry
		for _, name := range before {
			if name == s.path {
				continue
			}
			es, err := readFileEntries(name)
			if err != nil {
				return err
			}
			all = append(all, es...)
		}
		active, fi, off, err := readActive(s.path)
		if err != nil {
			return err
		}
		after, err := Files(s.path)
		if err != nil {
			return err
		}
		if !sameRotated(before, after, s.path) && attempt < 5 {
			continue // rotated while we were reading; try again
		}
		all = append(all, active...)
		start := 0
		if s.last != "" {
			for i := len(all) - 1; i >= 0; i-- {
				if all[i].Hash == s.last {
					start = i + 1
					break
				}
			}
		}
		for _, e := range all[start:] {
			if err := fn(e); err != nil {
				return err
			}
			s.last = e.Hash
		}
		s.fi, s.off, s.rescan = fi, off, false
		return nil
	}
}

func sameRotated(a, b []string, active string) bool {
	strip := func(x []string) []string {
		if n := len(x); n > 0 && x[n-1] == active {
			return x[:n-1]
		}
		return x
	}
	a, b = strip(a), strip(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func readActive(path string) ([]Entry, os.FileInfo, int64, error) {
	f, err := openFile(path, os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, 0, nil
	}
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, 0, err
	}
	es, n, err := readComplete(f, 0)
	return es, fi, n, err
}

// readComplete parses newline-terminated entries from r starting at off, returning the entries
// and the offset just past the last complete line.
func readComplete(f *os.File, off int64) ([]Entry, int64, error) {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, off, fmt.Errorf("read audit log: %w", err)
	}
	end := bytes.LastIndexByte(data, '\n') + 1
	var out []Entry
	for _, line := range bytes.Split(data[:end], []byte{'\n'}) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, off, fmt.Errorf("corrupt audit entry: %w", err)
		}
		out = append(out, e)
	}
	return out, off + int64(end), nil
}

func (s *follower) incremental(fn func(Entry) error) error {
	f, err := openFile(s.path, os.O_RDONLY, 0)
	if err != nil {
		s.rescan = true
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(fi, s.fi) {
		s.rescan = true
		return nil
	}
	es, off, err := readComplete(f, s.off)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := fn(e); err != nil {
			return err
		}
		s.last = e.Hash
	}
	s.off = off
	return nil
}
