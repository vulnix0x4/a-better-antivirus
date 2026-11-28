// Package paths centralises every on-disk location and name ABA uses.
//
// The installed footprint deliberately uses neutral names ("File Access Monitor")
// so that a stealer enumerating services or Program Files does not immediately
// spot a honeypot tool and skip its file-grabbing stage. This is low-profile,
// not hidden: everything is documented and visible to an administrator.
//
// Where things live, and how the operating system compares file names, is in
// paths_<os>.go: InstallDir, DataDir, the program file names, Long, FileID and
// whether names are compared ignoring case.
package paths

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	ProductName = "ABA"

	ServiceName        = "FileAccessMonitor"
	ServiceDisplayName = "File Access Monitor"
	// Anything running as you can read a service's description. It used to say
	// "watches decoy files": no need to tell a stealer what this is in so many words.
	ServiceDescription = "Monitors file access and reports unusual activity."
)

func InstalledCLI() string     { return filepath.Join(InstallDir(), CLIExe) }
func InstalledService() string { return filepath.Join(InstallDir(), ServiceExe) }

// InstalledApp is the desktop app, when it's installed (Windows only for
// now): next to the CLI, in the admin-only install folder.
func InstalledApp() string { return filepath.Join(InstallDir(), AppExe) }

func ConfigFile() string  { return filepath.Join(DataDir(), "config.json") }
func StateFile() string   { return filepath.Join(DataDir(), "state.json") }
func SecretsFile() string { return filepath.Join(DataDir(), "secrets.json") } // admin-only, and encrypted where the OS offers it
func AlertsDir() string   { return filepath.Join(DataDir(), "alerts") }

// EvidenceDir holds what the autopsy of a caught program saved (one folder
// per alert): admin-only, like everything in the data folder but public/.
func EvidenceDir() string { return filepath.Join(DataDir(), "evidence") }
func LogFile() string     { return filepath.Join(DataDir(), "service.log") }
func TestFile() string    { return filepath.Join(DataDir(), "pending-test.json") }

// ClipboardTestFile is how a bait put out for `aba clipboard test` went, when
// the guard caught nothing (clipbait.TestResult).
func ClipboardTestFile() string { return filepath.Join(DataDir(), "clipboard-test.json") }

// AppDir is the desktop app's own corner of the (admin-only) data folder.
// (Not its WebView2 profile: WebView2 runs its browser processes with the
// person's ordinary rights even for an elevated app, so the profile has to
// be somewhere they can write; see appsec.WebViewDir.)
func AppDir() string { return filepath.Join(DataDir(), "app") }

// AppShownFile is where the app, started by the service for alert id in a
// session, says it showed its window (or handed the alert to the copy
// already open there). Until it does, the service has the popup ready.
func AppShownFile(session uint32, id string) string {
	return filepath.Join(AppDir(), fmt.Sprintf("shown-%d-%s", session, id))
}

// AppOpenRequestFile is where a second start of the app in a session leaves
// its alert for the copy already open there.
func AppOpenRequestFile(session uint32) string {
	return filepath.Join(AppDir(), fmt.Sprintf("open-request-%d.json", session))
}

// PublicDir is the one corner of the data folder anyone may read.
func PublicDir() string        { return filepath.Join(DataDir(), "public") }
func PublicStatusFile() string { return filepath.Join(PublicDir(), "status.json") }

// Clean normalises a path for comparison (ignoring case where the operating
// system does).
func Clean(p string) string {
	p = filepath.Clean(p)
	if foldCase {
		p = strings.ToLower(p)
	}
	return p
}

// Same reports whether two paths refer to the same location.
func Same(a, b string) bool { return Clean(a) == Clean(b) }

// Under reports whether p is inside dir.
func Under(p, dir string) bool {
	if dir == "" {
		return false
	}
	p, dir = Clean(p), Clean(dir)
	if !strings.HasSuffix(dir, string(filepath.Separator)) {
		dir += string(filepath.Separator)
	}
	return strings.HasPrefix(p, dir)
}

// Key is the canonical form used to look paths up in maps.
func Key(p string) string { return Clean(Long(p)) }

// FoldsCase reports whether this operating system's file names ignore case
// (so a command line naming them does too).
func FoldsCase() bool { return foldCase }
