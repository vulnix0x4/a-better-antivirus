package baits

// Making baits look at home on macOS, and planting them safely.
//
// eslogger reports every open on the Mac, so a bait needs nothing put on the
// file itself to be watched: its tripwire is just being in the list the
// service watches (baitsChanged).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SetTripwire checks that the bait is an ordinary file: watching it is the
// service's list.
func SetTripwire(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't an ordinary file", path)
	}
	return nil
}

// HasTripwire: a bait in the list is watched.
func HasTripwire(path string) (bool, error) { return true, nil }

// ClearTripwire: nothing on the file to take off.
func ClearTripwire(path string) error { return nil }

// setTimes sets when a file was created, last opened and last changed. macOS
// has no call to set the creation time, but moves it back by itself when a
// file's modification time is set earlier than it: so the modification time
// goes to the creation time first, then to the time it should have.
func setTimes(path string, created, accessed, written time.Time) {
	set := func(a, m time.Time) {
		ts := []unix.Timespec{unix.NsecToTimespec(a.UnixNano()), unix.NsecToTimespec(m.UnixNano())}
		unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
	}
	if !created.IsZero() && created.Before(written) {
		set(accessed, created)
	}
	set(accessed, written)
}

// getTimes reads when a file or folder was created and last changed.
func getTimes(path string) (created, written time.Time, ok bool) {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil {
		return created, written, false
	}
	return time.Unix(st.Btim.Unix()), time.Unix(st.Mtim.Unix()), true
}

// ownedBy gives a planted file the permissions files of that kind have in a
// home folder. (It's created by its owner already: see asOwner.) Dot-folders
// and what's in them are private to their owner, the rest readable.
func ownedBy(path, userID string) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return
	}
	hidden := false
	for _, part := range strings.Split(filepath.Clean(path), "/") {
		hidden = hidden || strings.HasPrefix(part, ".")
	}
	var want os.FileMode
	switch {
	case fi.IsDir() && hidden:
		want = 0o700
	case fi.IsDir():
		want = 0o755
	case hidden:
		want = 0o600
	default:
		want = 0o644
	}
	if fi.Mode().Perm() != want {
		os.Chmod(path, want)
	}
}

// indexedLikeFolder: Spotlight indexes a bait like anything else in its
// folder, which is what a real file would get. (Spotlight's reads are never
// reported.)
func indexedLikeFolder(path string) {}

// controller is who decides what goes on at path: the owner of the first
// thing on the way to it (or it itself) that isn't root's.
func controller(path string) (uid, gid uint32) {
	cur := "/"
	for _, part := range strings.Split(strings.Trim(filepath.Clean(path), "/"), "/") {
		cur = filepath.Join(cur, part)
		var st unix.Stat_t
		if unix.Lstat(cur, &st) != nil {
			return 0, 0 // doesn't exist (yet): everything above it is root's
		}
		if st.Uid != 0 {
			return st.Uid, st.Gid
		}
	}
	return 0, 0
}

// asOwner runs fn, which plants or removes files at or around path, with the
// file rights of whoever controls path (see controller) instead of root's.
//
// A program running as you can put a link where a bait is about to be
// planted, pointing at a file of the system's. Root's writes would follow
// it; yours can't. So the work is done as you: macOS lets root give one
// thread another user's rights (pthread_setugid_np, the call file servers
// use), and only that thread runs fn.
func asOwner(path string, fn func()) error {
	uid, gid := controller(path)
	if uid == 0 || os.Geteuid() != 0 {
		fn()
		return nil
	}
	// On a goroutine of its own, locked to its thread: if the thread can't be
	// given back root's rights afterwards, the goroutine ends still locked and
	// Go throws the thread away instead of running anything else on it.
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// KAUTH_UID_NONE / KAUTH_GID_NONE (~0 - 100): back to the process's own.
		const none = uintptr(^uint32(0) - 100)
		if _, _, e := syscall.RawSyscall(unix.SYS_SETTID, uintptr(uid), uintptr(gid), 0); e != 0 {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("couldn't act as the owner of %s (%v), so nothing was changed there", path, e)
			return
		}
		restored := false
		defer func() {
			if restored {
				runtime.UnlockOSThread()
			}
		}()
		// The thread's rights are what getuid answers with: check they took.
		if unix.Geteuid() != int(uid) {
			errc <- errors.New("couldn't act as the owner of " + path + ": the kernel kept root's rights")
		} else {
			fn()
			errc <- nil
		}
		_, _, e := syscall.RawSyscall(unix.SYS_SETTID, none, none, 0)
		restored = e == 0 && unix.Geteuid() == 0
	}()
	return <-errc
}
