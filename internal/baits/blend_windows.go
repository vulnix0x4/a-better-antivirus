package baits

import (
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// A bait's tripwire on Windows is an audit rule on the file (see
// winsec.SetBaitAudit): reads of it land in the Security event log.

// SetTripwire puts the tripwire on a bait file. Requires admin.
func SetTripwire(path string) error { return winsec.SetBaitAudit(path) }

// HasTripwire reports whether the file still has its tripwire.
func HasTripwire(path string) (bool, error) { return winsec.HasBaitAudit(path) }

// ClearTripwire takes the tripwire off again.
func ClearTripwire(path string) error { return winsec.ClearAudit(path) }

func fileTime(t time.Time) *windows.Filetime {
	ft := windows.NsecToFiletime(t.UnixNano())
	return &ft
}

func setTimes(path string, created, accessed, written time.Time) {
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.SetFileTime(h, fileTime(created), fileTime(accessed), fileTime(written))
}

func getTimes(path string) (created, written time.Time, ok bool) {
	var d windows.Win32FileAttributeData
	p, err := windows.UTF16PtrFromString(path)
	if err != nil || windows.GetFileAttributesEx(p, windows.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&d))) != nil {
		return created, written, false
	}
	return time.Unix(0, d.CreationTime.Nanoseconds()), time.Unix(0, d.LastWriteTime.Nanoseconds()), true
}

// ownedBy makes sid the owner of path, when it isn't already. (Needs the
// restore privilege, which an elevated installer and the service have.)
func ownedBy(path, sid string) {
	if sid == "" {
		return
	}
	want, err := windows.StringToSid(sid)
	if err != nil {
		return
	}
	if sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
		if cur, _, err := sd.Owner(); err == nil && cur != nil && cur.Equals(want) {
			return
		}
	}
	if winsec.EnablePrivilege("SeRestorePrivilege") != nil {
		return
	}
	windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, want, nil, nil, nil)
}

// indexedLikeFolder gives a bait the same "index this file" setting as the
// folder it's in (which is what any file created there gets).
func indexedLikeFolder(path string) {
	attrs := func(p string) (uint32, bool) {
		u, _ := windows.UTF16PtrFromString(p)
		a, err := windows.GetFileAttributes(u)
		return a, err == nil
	}
	fa, ok1 := attrs(path)
	da, ok2 := attrs(filepath.Dir(path))
	const noIndex = windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	if !ok1 || !ok2 || fa&noIndex == da&noIndex {
		return
	}
	u, _ := windows.UTF16PtrFromString(path)
	windows.SetFileAttributes(u, fa&^noIndex|da&noIndex)
}
