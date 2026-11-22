package paths

// Where ABA lives on macOS. Like on Windows and Linux it goes by a neutral
// name ("File Access Monitor"), in the folder macOS keeps such things in.
//
// The program is an app bundle that never shows a window. It's a bundle so
// that it gets a name and a place in System Settings' Full Disk Access list,
// which ABA needs (see svcctl_darwin.go): the service runs Apple's eslogger,
// and macOS only lets a program with Full Disk Access do that.

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	// One program file: the app bundle's main program, which the service runs
	// and which /usr/local/bin/aba links to. (A second copy inside a signed
	// bundle would be a second piece of signed code, and copying one over the
	// other would break the signature.)
	CLIExe     = "famsvc"
	ServiceExe = "famsvc"

	// CommandName is what people type.
	CommandName = "aba"

	// The Mac's file systems ignore case unless a volume was formatted
	// otherwise.
	foldCase = true

	// BundleID names the program to macOS (Full Disk Access, launchd).
	BundleID = "com.fileaccessmonitor.service"
)

// SupportDir holds everything of ABA's: the app and its data. Only root can
// write there.
func SupportDir() string { return "/Library/Application Support/" + ServiceDisplayName }

// AppBundle is the program as macOS sees it.
func AppBundle() string { return filepath.Join(SupportDir(), ServiceDisplayName+".app") }

// InstallDir holds the program files, inside the bundle.
func InstallDir() string { return filepath.Join(AppBundle(), "Contents", "MacOS") }

// DataDir holds config, state, alerts and the log. Only root can read them:
// they list every bait and every program you trusted. What `aba` shows
// without root comes from PublicStatusFile.
func DataDir() string { return filepath.Join(SupportDir(), "Data") }

// Long has nothing to expand: there are no 8.3 short names here.
func Long(p string) string { return p }

// FileID identifies the file at p whatever name it's reached by (two hard
// links to one file have the same ID): its device and inode. It doesn't open
// the file and doesn't follow a symbolic link at p.
func FileID(p string) (string, bool) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return "", false
	}
	return fmt.Sprintf("%x:%x", uint64(st.Dev), st.Ino), true
}
