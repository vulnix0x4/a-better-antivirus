package paths

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	installDirName = "File Access Monitor"
	dataDirName    = "FileAccessMonitor"

	CLIExe     = "aba.exe"     // what users type; on PATH
	ServiceExe = "famsvc.exe"  // identical copy the service runs from
	AppExe     = "aba-app.exe" // the desktop app (optional: installed with it)

	// Windows compares file names ignoring case.
	foldCase = true
)

// InstallDir is admin-write-only (Program Files), so the SYSTEM service can
// never be made to run attacker-controlled code.
func InstallDir() string {
	return filepath.Join(programFiles(), installDirName)
}

// DataDir holds config, state, alerts and logs. Only SYSTEM and
// Administrators can get in: it lists every bait and every program you
// trusted, which is exactly what a stealer would like to read. What `aba`
// shows without admin rights comes from PublicStatusFile.
func DataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, dataDirName)
}

func programFiles() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && p != "" {
		return p
	}
	if p := os.Getenv("ProgramFiles"); p != "" {
		return p
	}
	return `C:\Program Files`
}

// Long expands 8.3 short names (C:\Users\VULNIX~1 -> C:\Users\vulnix0x4) so
// the same file always compares equal. It only queries directory entries,
// never file contents, so it's safe to call on baits. Paths that don't exist
// are returned unchanged.
func Long(p string) string {
	if !strings.Contains(p, "~") {
		return p
	}
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}

// FileID identifies the file at p whatever name it's reached by (two hard
// links to one file have the same ID). It asks only for the file's
// attributes: nothing is read, no audit event, no oplock broken.
func FileID(p string) (string, bool) {
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", false
	}
	h, err := windows.CreateFile(u, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &fi) != nil {
		return "", false
	}
	const hexd = "0123456789abcdef"
	b := make([]byte, 0, 24)
	for _, v := range []uint32{fi.VolumeSerialNumber, fi.FileIndexHigh, fi.FileIndexLow} {
		for sh := 28; sh >= 0; sh -= 4 {
			b = append(b, hexd[(v>>uint(sh))&0xf])
		}
	}
	return string(b), true
}
