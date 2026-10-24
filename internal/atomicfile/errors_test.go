package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteErrorsLeaveNoTempFiles(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "missing", "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}

	// The target is a directory: the final rename fails and the temp file must be cleaned up.
	dir := t.TempDir()
	target := filepath.Join(dir, "d")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Write(target, []byte("x"), 0o600); err == nil {
		t.Fatal("write over a directory succeeded")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "d" {
		t.Fatalf("temp files left behind: %v", ents)
	}
}
