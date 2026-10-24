package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const rotatedTimeLayout = "20060102T150405Z"

var rotatedSuffix = regexp.MustCompile(`^(\d{8}T\d{6}Z)-(\d+)$`)

func splitStem(path string) (dir, stem, ext string) {
	dir = filepath.Dir(path)
	base := filepath.Base(path)
	ext = filepath.Ext(base)
	return dir, strings.TrimSuffix(base, ext), ext
}

// rotatedName is "<stem>-<UTC yyyymmddThhmmssZ>-<last seq><ext>" next to the active file.
func rotatedName(path string, t time.Time, seq uint64) string {
	dir, stem, ext := splitStem(path)
	return filepath.Join(dir, fmt.Sprintf("%s-%s-%d%s", stem, t.Format(rotatedTimeLayout), seq, ext))
}

// Files returns the rotated files (oldest first, ordered by their last seq) followed by the
// active file if it exists.
func Files(path string) ([]string, error) {
	dir, stem, ext := splitStem(path)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list audit dir: %w", err)
	}
	type rot struct {
		name string
		seq  uint64
	}
	var rots []rot
	prefix := stem + "-"
	for _, de := range ents {
		n := de.Name()
		if de.IsDir() || !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ext) {
			continue
		}
		m := rotatedSuffix.FindStringSubmatch(strings.TrimSuffix(strings.TrimPrefix(n, prefix), ext))
		if m == nil {
			continue
		}
		seq, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			continue
		}
		rots = append(rots, rot{filepath.Join(dir, n), seq})
	}
	sort.Slice(rots, func(i, j int) bool {
		if rots[i].seq != rots[j].seq {
			return rots[i].seq < rots[j].seq
		}
		return rots[i].name < rots[j].name
	})
	out := make([]string, 0, len(rots)+1)
	for _, r := range rots {
		out = append(out, r.name)
	}
	if _, err := os.Stat(path); err == nil {
		out = append(out, path)
	}
	return out, nil
}

// scanFile calls fn for each non-empty line of the file with its 1-based line number.
func scanFile(name string, fn func(line []byte, lineNo int) error) error {
	f, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64*1024)
	lineNo := 0
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) > 0 {
				if ferr := fn(trimmed, lineNo); ferr != nil {
					return ferr
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
	}
}

func readFileEntries(name string) ([]Entry, error) {
	var out []Entry
	err := scanFile(name, func(line []byte, lineNo int) error {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("%s:%d: corrupt audit entry: %w", filepath.Base(name), lineNo, err)
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

// ReadAll returns every entry across the rotated set and the active file, oldest first.
func ReadAll(path string) ([]Entry, error) {
	files, err := Files(path)
	if err != nil {
		return nil, err
	}
	var all []Entry
	for _, name := range files {
		es, err := readFileEntries(name)
		if err != nil {
			return nil, err
		}
		all = append(all, es...)
	}
	return all, nil
}

// Tail returns the last n entries (all when n <= 0) in chronological order, across rotation.
func Tail(path string, n int) ([]Entry, error) {
	files, err := Files(path)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for i := len(files) - 1; i >= 0; i-- {
		es, err := readFileEntries(files[i])
		if err != nil {
			return nil, err
		}
		out = append(es, out...)
		if n > 0 && len(out) >= n {
			break
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// Head returns the newest entry (unverified), or nil when the log is empty.
func Head(path string) (*Entry, error) {
	files, err := Files(path)
	if err != nil {
		return nil, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		e, err := lastEntryOf(files[i])
		if err != nil {
			return nil, err
		}
		if e != nil {
			return e, nil
		}
	}
	return nil, nil
}

func lastEntryOf(name string) (*Entry, error) {
	f, err := os.Open(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	line, err := lastLine(f, fi.Size())
	if err != nil || line == nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return nil, fmt.Errorf("%s: corrupt final audit entry: %w", filepath.Base(name), err)
	}
	return &e, nil
}

// lastLine returns the last non-empty newline-terminated line in f[0:size].
func lastLine(f io.ReaderAt, size int64) ([]byte, error) {
	end, err := completeLength(f, size)
	if err != nil {
		return nil, err
	}
	const chunk = 64 * 1024
	var buf []byte
	pos := end
	for pos > 0 {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		b := make([]byte, n)
		if _, err := f.ReadAt(b, pos-n); err != nil && err != io.EOF {
			return nil, fmt.Errorf("read audit log: %w", err)
		}
		pos -= n
		buf = append(b, buf...)
		trimmed := bytes.TrimRight(buf, "\r\n")
		if len(trimmed) == 0 {
			continue
		}
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
		if pos == 0 {
			return trimmed, nil
		}
	}
	return nil, nil
}

// completeLength returns the length of f[0:size] up to and including its last newline, i.e.
// excluding any torn final line.
func completeLength(f io.ReaderAt, size int64) (int64, error) {
	const chunk = 64 * 1024
	pos := size
	for pos > 0 {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		b := make([]byte, n)
		if _, err := f.ReadAt(b, pos-n); err != nil && err != io.EOF {
			return 0, fmt.Errorf("read audit log: %w", err)
		}
		if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
			return pos - n + int64(i) + 1, nil
		}
		pos -= n
	}
	return 0, nil
}

// chainHead returns the newest hash and seq across all files. Legacy entries without a seq are
// numbered by position, matching the verifier.
func chainHead(path string) (string, uint64, error) {
	e, err := Head(path)
	if err != nil || e == nil {
		return "", 0, err
	}
	if e.Seq != 0 {
		return e.Hash, e.Seq, nil
	}
	var seq uint64
	files, err := Files(path)
	if err != nil {
		return "", 0, err
	}
	for _, name := range files {
		if err := scanFile(name, func(line []byte, _ int) error {
			var x struct {
				Seq uint64 `json:"seq"`
			}
			if err := json.Unmarshal(line, &x); err != nil {
				return fmt.Errorf("corrupt audit entry: %w", err)
			}
			seq = nextSeq(seq, x.Seq)
			return nil
		}); err != nil {
			return "", 0, err
		}
	}
	return e.Hash, seq, nil
}

func nextSeq(prev, got uint64) uint64 {
	if got != 0 {
		return got
	}
	return prev + 1
}
