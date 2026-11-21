package baits

// Planting on Linux: making a bait look used, and doing it without letting a
// program running as you turn ABA's root rights against the system.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A bait's tripwire on Linux isn't on the file: the service asks the kernel
// to tell it about every open of that file (fanotify, see package fanwatch),
// and the kernel keeps that with the file itself, whatever name it's reached
// by. Only the service's own process can set or see those marks, so it
// plugs itself in here; in the CLI these have nothing to do (the service
// marks every bait when it's told the baits changed).
var (
	// Watch marks a bait file; Watched reports whether the file at path is
	// marked. Set by the service.
	Watch   func(path string) error
	Watched func(path string) bool
)

// SetTripwire has the service watch a bait file. A bait is always an
// ordinary file: never a link to somewhere else.
func SetTripwire(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't an ordinary file", path)
	}
	if Watch != nil {
		return Watch(path)
	}
	return nil
}

// HasTripwire reports whether the file is being watched. Only the service
// can tell (see above); elsewhere the answer is yes, and `aba doctor` shows
// what the service last counted.
func HasTripwire(path string) (bool, error) {
	if Watched != nil {
		return Watched(path), nil
	}
	return true, nil
}

// ClearTripwire has nothing to take off: the kernel forgets a file's mark
// when the file goes, and the service drops what's no longer a bait.
func ClearTripwire(path string) error { return nil }

// setTimes sets when a file or folder was last opened and last changed. Linux
// keeps no settable "created" time: the file's birth and change times stay
// the moment it was planted, which a stealer that lists them can see.
func setTimes(path string, created, accessed, written time.Time) {
	ts := []unix.Timespec{unix.NsecToTimespec(accessed.UnixNano()), unix.NsecToTimespec(written.UnixNano())}
	unix.UtimesNanoAt(unix.AT_FDCWD, path, ts, unix.AT_SYMLINK_NOFOLLOW)
}

// getTimes reads when a file or folder was created (as far as the file
// system says) and last changed.
func getTimes(path string) (created, written time.Time, ok bool) {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil {
		return created, written, false
	}
	written = time.Unix(st.Mtim.Unix())
	created = time.Unix(st.Ctim.Unix())
	var sx unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &sx) == nil && sx.Mask&unix.STATX_BTIME != 0 {
		created = time.Unix(sx.Btime.Sec, int64(sx.Btime.Nsec))
	}
	return created, written, true
}

// ownedBy gives a planted file or folder the permissions such a thing
// normally has. (Whose it is was settled when it was made: see asOwner.)
// What apps keep under a hidden folder (~/.config, ~/.ssh) is private to you;
// a document in your home folder is readable like its neighbours.
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

// indexedLikeFolder: Linux has no per-file indexing flag.
func indexedLikeFolder(path string) {}

// controller is who decides what's at path: the owner of the first folder
// (or link) on the way to it that isn't root's. 0 if root controls all of it.
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
// file-system rights of whoever controls that place instead of root's.
//
// ABA plants baits as root in folders that belong to you, and so to anything
// running as you. A program there could swap a folder for a link to
// /etc/cron.d just before ABA writes into it, and have root create or delete
// files where it chooses. Doing the work as the folder's owner takes that
// away: a link then leads nowhere its maker couldn't go already. It also
// makes every bait yours from the start, like the files around it.
//
// Only this thread changes identity (the kernel keeps one per thread), and
// only for file access: it stays root for everything else.
func asOwner(path string, fn func()) error {
	uid, gid := controller(path)
	if uid == 0 || os.Geteuid() != 0 {
		fn()
		return nil
	}
	runtime.LockOSThread()
	// (Not unlocked if the way back fails: Go then retires the thread instead
	// of running other work on it.)
	groups, err := unix.Getgroups()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	restore := func() bool {
		a := rawSetGroups(groups)
		_, _, e1 := unix.RawSyscall(unix.SYS_SETFSGID, 0, 0, 0)
		_, _, e2 := unix.RawSyscall(unix.SYS_SETFSUID, 0, 0, 0)
		cur, _, _ := unix.RawSyscall(unix.SYS_SETFSUID, ^uintptr(0), 0, 0)
		return a == nil && e1 == 0 && e2 == 0 && cur == 0
	}
	fail := func(what string, e error) error {
		if restore() {
			runtime.UnlockOSThread()
		}
		return fmt.Errorf("couldn't act as the owner of %s (%s: %v), so nothing was changed there", path, what, e)
	}
	if err := rawSetGroups([]int{int(gid)}); err != nil {
		return fail("groups", err)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETFSGID, uintptr(gid), 0, 0); e != 0 {
		return fail("group", e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETFSUID, uintptr(uid), 0, 0); e != 0 {
		return fail("user", e)
	}
	// setfsuid reports nothing useful: ask again what it is now.
	if cur, _, _ := unix.RawSyscall(unix.SYS_SETFSUID, ^uintptr(0), 0, 0); uint32(cur) != uid {
		return fail("user", errors.New("the kernel kept root"))
	}
	defer func() {
		if restore() {
			runtime.UnlockOSThread()
		}
	}()
	fn()
	return nil
}

// rawSetGroups sets this thread's supplementary groups. (The library call
// would change every thread of the process.)
func rawSetGroups(gids []int) error {
	g := make([]uint32, len(gids))
	for i, v := range gids {
		g[i] = uint32(v)
	}
	var p uintptr
	if len(g) > 0 {
		p = uintptr(unsafe.Pointer(&g[0]))
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(g)), p, 0); e != 0 {
		return e
	}
	runtime.KeepAlive(g)
	return nil
}
