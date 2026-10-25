//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// openFile opens an audit log file with FILE_SHARE_DELETE so that another process (or a
// follower in this one) holding it open does not prevent rotation from renaming it. Go's
// os.OpenFile omits that share mode on Windows.
func openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = windows.GENERIC_READ
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	default:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		// Like os.OpenFile: append-only writes are atomic at end of file across handles.
		access &^= windows.GENERIC_WRITE
		access |= windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE
	}
	disposition := uint32(windows.OPEN_EXISTING)
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = windows.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		disposition = windows.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		disposition = windows.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		disposition = windows.TRUNCATE_EXISTING
	}
	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		attrs = windows.FILE_ATTRIBUTE_READONLY
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	h, err := windows.CreateFile(p, access, share, nil, disposition, attrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}

// truncateFile shrinks the audit log at name to size bytes. It uses a separate write handle
// because the writer's own handle is append-only, which Windows does not allow to truncate.
func truncateFile(name string, size int64) error {
	f, err := openFile(name, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	terr := f.Truncate(size)
	cerr := f.Close()
	if terr != nil {
		return terr
	}
	return cerr
}
