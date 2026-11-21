package procinfo

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide; until it does, each
// piece says so (or gives the cautious answer where it can't return an error).

import (
	"path/filepath"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

var errNotYet = platform.Unsupported("inspecting and controlling processes")

// ---- looking at processes ----

// Snapshot lists all processes.
func Snapshot() (map[uint32]Entry, error) { return nil, errNotYet }

// CreateTime says when a process started (see Entry.CreateTime). Together
// with the PID it identifies a process for good: PIDs get reused.
func CreateTime(pid uint32) (int64, error) { return 0, errNotYet }

// ImagePath returns the full path of the process executable.
func ImagePath(pid uint32) (string, error) { return "", errNotYet }

// CommandLine returns the process command line.
func CommandLine(pid uint32) (string, error) { return "", errNotYet }

// Alive reports whether pid exists and (if createTime != 0) is the same process.
func Alive(pid uint32, createTime int64) bool { return false }

// RunningImage lists the processes running the executable at path.
func RunningImage(path string) []uint32 { return nil }

// BaseName is the file name of a program's path, for display.
func BaseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

// systemPID reports whether pid is one ABA must never touch whatever it is
// (the kernel's own processes).
func systemPID(pid uint32) bool { return pid <= 2 }

// ---- who a process runs as ----

// SelfElevated reports whether this process has administrator (root) rights.
func SelfElevated() bool { return false }

// Elevated reports whether pid runs with administrator (root) rights. When it
// can't tell it says yes: ABA is careful with those.
func Elevated(pid uint32) bool { return true }

// UserSession reports whether pid is an ordinary user's program rather than
// a system service.
func UserSession(pid uint32) bool { return false }

// UserID returns the account a process runs as, in the form ServiceAccount
// and config.UserInfo.SID use.
func UserID(pid uint32) (string, error) { return "", errNotYet }

// ServiceAccount reports whether the account with this ID is one that system
// services run as, not a person.
func ServiceAccount(id string) bool { return false }

// ---- freezing ----

// Suspend freezes a process, Resume lets it run again.
func Suspend(pid uint32) error { return errNotYet }
func Resume(pid uint32) error  { return errNotYet }

// Kill terminates a process.
func Kill(pid uint32) error { return errNotYet }

// Hold locks a frozen process frozen, so that no other program running as the
// same user can let it run again; only this process can (Unhold, DropHolds).
func Hold(pid uint32, createTime int64) error { return errNotYet }

// Unhold releases this process's hold on pid, if it has one.
func Unhold(pid uint32, createTime int64) {}

// Held reports how many processes this process holds.
func Held() int { return 0 }

// DropHolds lets go of the holds made before madeBefore that keep (given a
// HoldName) no longer wants. It never kills anything.
func DropHolds(madeBefore time.Time, keep func(name string) bool) {}

// ---- forensics ----

// Connections lists the sockets the given processes have open.
func Connections(pids []uint32) ([]Conn, error) { return nil, errNotYet }

// InjectedCode looks inside a running process for code that isn't from any
// file on disk (a stealer running inside a legitimate program) and describes
// what it found.
func InjectedCode(pid uint32) (detail string, found bool) { return "", false }

// SideLoaded looks for a library that nobody vouches for (see signed), loaded
// by pid from its own program's folder, and returns its path.
func SideLoaded(pid uint32, image string, signed func(path string) bool) (lib string, found bool) {
	return "", false
}
