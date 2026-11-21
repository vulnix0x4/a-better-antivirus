// Package paths centralises every on-disk location and name ABA uses.
//
// The installed footprint deliberately uses neutral names ("File Access Monitor")
// so that a stealer enumerating services or Program Files does not immediately
// spot a honeypot tool and skip its file-grabbing stage. This is low-profile,
// not hidden: everything is documented and visible to an administrator.
package paths

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	ProductName = "ABA"

	ServiceName        = "FileAccessMonitor"
	ServiceDisplayName = "File Access Monitor"
	// Anything running as you can read a service's description. It used to say
	// "watches decoy files": no need to tell a stealer what this is in so many words.
	ServiceDescription = "Monitors file access and reports unusual activity."

	installDirName = "File Access Monitor"
	dataDirName    = "FileAccessMonitor"

	CLIExe     = "aba.exe"    // what users type; on PATH
	ServiceExe = "famsvc.exe" // identical copy the service runs from
)

// InstallDir is admin-write-only (Program Files), so the SYSTEM service can
// never be made to run attacker-controlled code.
func InstallDir() string {
	return filepath.Join(programFiles(), installDirName)
}

func InstalledCLI() string     { return filepath.Join(InstallDir(), CLIExe) }
func InstalledService() string { return filepath.Join(InstallDir(), ServiceExe) }

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

func ConfigFile() string  { return filepath.Join(DataDir(), "config.json") }
func StateFile() string   { return filepath.Join(DataDir(), "state.json") }
func SecretsFile() string { return filepath.Join(DataDir(), "secrets.json") } // admin-only ACL + DPAPI
func AlertsDir() string   { return filepath.Join(DataDir(), "alerts") }
func LogFile() string     { return filepath.Join(DataDir(), "service.log") }
func TestFile() string    { return filepath.Join(DataDir(), "pending-test.json") }

// PublicDir is the one corner of the data folder anyone may read.
func PublicDir() string        { return filepath.Join(DataDir(), "public") }
func PublicStatusFile() string { return filepath.Join(PublicDir(), "status.json") }

func programFiles() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && p != "" {
		return p
	}
	if p := os.Getenv("ProgramFiles"); p != "" {
		return p
	}
	return `C:\Program Files`
}

// Clean normalises a path for case-insensitive comparison.
func Clean(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// Same reports whether two paths refer to the same location (case-insensitive).
func Same(a, b string) bool { return Clean(a) == Clean(b) }

// Under reports whether p is inside dir (case-insensitive).
func Under(p, dir string) bool {
	if dir == "" {
		return false
	}
	p, dir = Clean(p), Clean(dir)
	if !strings.HasSuffix(dir, `\`) {
		dir += `\`
	}
	return strings.HasPrefix(p, dir)
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

// Key is the canonical form used to look paths up in maps.
func Key(p string) string { return Clean(Long(p)) }

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
