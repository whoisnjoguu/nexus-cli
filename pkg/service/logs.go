package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// followInterval is how often TailFile polls a followed file.
var followInterval = 250 * time.Millisecond

// TailFile writes the last opts.Lines lines of path to w (all of it when Lines <= 0) and, with
// opts.Follow, keeps copying appended data until ctx is done. A truncated or rotated file is
// re-read from the start.
func TailFile(ctx context.Context, w io.Writer, path string, opts LogOptions) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && opts.Follow {
		f, err = waitForFile(ctx, path)
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no service log at %s yet", path)
		}
		return err
	}
	defer func() { f.Close() }()

	start, err := tailOffset(f, opts.Lines)
	if err != nil {
		return err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}
	off := start
	n, err := io.Copy(w, f)
	off += n
	if err != nil || !opts.Follow {
		return err
	}

	t := time.NewTicker(followInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue // rotated away; wait for it to reappear
		}
		cur, err := f.Stat()
		if err != nil {
			return err
		}
		if !os.SameFile(fi, cur) || fi.Size() < off {
			nf, err := os.Open(path)
			if err != nil {
				continue
			}
			f.Close()
			f, off = nf, 0
		}
		n, err := io.Copy(w, f)
		off += n
		if err != nil {
			return err
		}
	}
}

func waitForFile(ctx context.Context, path string) (*os.File, error) {
	t := time.NewTicker(followInterval)
	defer t.Stop()
	for {
		f, err := os.Open(path)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return f, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-t.C:
		}
	}
}

// tailOffset returns the offset of the start of the last n lines of f.
func tailOffset(f *os.File, n int) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	const chunk = 8 << 10
	buf := make([]byte, chunk)
	pos := size
	newlines := 0
	for pos > 0 {
		sz := int64(chunk)
		if pos < sz {
			sz = pos
		}
		pos -= sz
		if _, err := f.ReadAt(buf[:sz], pos); err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		b := buf[:sz]
		for i := len(b) - 1; i >= 0; i-- {
			if b[i] != '\n' {
				continue
			}
			// A newline that ends the file terminates the last line rather than starting one.
			if pos+int64(i) == size-1 {
				continue
			}
			newlines++
			if newlines == n {
				return pos + int64(i) + 1, nil
			}
		}
	}
	return 0, nil
}
