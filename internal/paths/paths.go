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
	ServiceDescription = "Watches decoy files and reacts when something reads them (A Better Antivirus)."

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

// DataDir holds config, state and alerts. SYSTEM/Administrators can write,
// Users can read (so the notifier and `aba status` work unelevated).
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
