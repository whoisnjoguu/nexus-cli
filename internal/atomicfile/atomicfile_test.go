package atomicfile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestWriteDefaultsAndPreservesMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := Write(p, []byte("a"), 0); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("default mode = %v", fi.Mode().Perm())
		}
		if err := os.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := Write(p, []byte("b"), 0); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "b" {
		t.Fatalf("content = %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode not preserved: %v", fi.Mode().Perm())
		}
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}

func TestWriteThroughSymlinkKeepsLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(link, []byte("y"), 0); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced by a regular file")
	}
	if b, _ := os.ReadFile(real); string(b) != "y" {
		t.Fatalf("target = %q", b)
	}
}

func TestWriteNeverPartiallyRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	a := bytes.Repeat([]byte("a"), 256<<10)
	b := bytes.Repeat([]byte("b"), 128<<10)
	if err := Write(p, a, 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			data := a
			if i%2 == 0 {
				data = b
			}
			if err := Write(p, data, 0); err != nil {
				t.Error(err)
				return
			}
		}
		close(stop)
	}()
	for {
		select {
		case <-stop:
			wg.Wait()
			return
		default:
		}
		got, err := os.ReadFile(p)
		if err != nil {
			if runtime.GOOS == "windows" {
				continue // sharing violations while renaming
			}
			t.Fatal(err)
		}
		if !bytes.Equal(got, a) && !bytes.Equal(got, b) {
			t.Fatalf("partial read: %d bytes", len(got))
		}
	}
}
