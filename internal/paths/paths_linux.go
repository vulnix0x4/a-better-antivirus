package paths

// Where ABA lives on Linux. The names are the neutral ones the Windows install
// uses ("File Access Monitor"), in the places Linux keeps such things: all of
// them belong to root, so nothing running as you can change the program the
// service runs or read what it knows.

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	CLIExe     = "aba"     // what people type; /usr/local/bin/aba links to it
	ServiceExe = "famsvc"  // identical copy the service runs from
	AppExe     = "aba-app" // no desktop app on Linux yet

	// Linux file systems tell File.txt and file.txt apart.
	foldCase = false
)

// InstallDir holds the program. Only root can write there, so the root
// service can never be made to run someone else's code.
func InstallDir() string { return "/usr/local/lib/file-access-monitor" }

// DataDir holds config, state, alerts and the log. Only root can read them:
// they list every bait and every program you trusted, which is exactly what a
// stealer would like to know. What `aba` shows without root comes from
// PublicStatusFile.
func DataDir() string { return "/var/lib/file-access-monitor" }

// RunDir holds what only matters until the next restart of the machine: which
// control group each frozen process came from.
func RunDir() string { return "/run/file-access-monitor" }

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
	return fmt.Sprintf("%x:%x", uint64(st.Dev), uint64(st.Ino)), true
}
