// Package fanwatch notices a bait being opened on Linux, with fanotify
// permission events.
//
// ABA marks each bait file and asks for FAN_OPEN_PERM. From then on, whenever
// any program opens that file, the kernel stops it inside the open(), tells
// ABA which process it is, and waits for "allow" or "deny". That is the
// "opener is held" case of package detect, without any guessing: Windows
// needs an oplock and a hunt through thread states to get the same thing.
//
// What a mark covers, and what it can't be dodged with:
//
//   - It's on the file itself (its inode), not on a name. A hard link, or the
//     bait renamed and opened under its new name, is the same file: the open
//     is reported, and Event.Alias says which name was used.
//   - Every way of getting at the contents starts with an open: read, mmap,
//     executing the file, io_uring's openat, opening another process's
//     descriptor through /proc/<pid>/fd. All of them are reported. An O_PATH
//     open isn't, and can't read; turning it into a real descriptor is an open.
//   - The opener can't ask not to be held, and can't see the mark.
//   - A file put in a bait's place (an editor that saves by writing a new
//     file, or something replacing it) is a different file with no mark: Sync
//     marks whatever is at the bait's path now, and the service calls it when
//     the baits are checked.
//
// Kernels built without permission events get plain FAN_OPEN notifications
// instead: the open is reported with the same detail, a moment after it
// happened (Event.Held is false).
package fanwatch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Event is one open of a bait.
type Event struct {
	PID   uint32
	Path  string // the bait
	Alias string // the name it was opened by, when that isn't the bait's own
	At    time.Time
	Held  bool // the opener is stopped inside its open until OnOpen returns
}

type fileID struct{ dev, ino uint64 }

// Watcher holds the marks and reads the events.
type Watcher struct {
	// OnOpen is called for every open of a bait by another process, each in
	// a goroutine of its own. For a held opener, the open goes ahead when it
	// returns: refused if it returns true.
	OnOpen func(ev Event) (deny bool)
	// TimedOut answers for an OnOpen that takes longer than Timeout: should
	// the open be refused? (The opener can't be left waiting: a program stuck
	// in open() forever is worse than a late verdict.)
	TimedOut func(ev Event) (deny bool)
	Timeout  time.Duration
	Logf     func(format string, args ...any)

	fd   int
	held bool
	wake [2]int // a pipe: writing to it stops Run

	mu     sync.Mutex
	byID   map[fileID]string // marked file -> bait path
	byPath map[string]fileID
	real   map[string]string // bait path -> its path with links resolved
	want   int
	closed bool
}

// New opens a fanotify group. It needs root.
func New() (*Watcher, error) {
	w := &Watcher{Timeout: 3 * time.Second, byID: map[fileID]string{}, byPath: map[string]fileID{}, real: map[string]string{}}
	const fflags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_LARGEFILE
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS, fflags)
	if err == nil {
		// The group exists; whether permission events are compiled in only
		// shows when one is asked for.
		if perr := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM, unix.AT_FDCWD, "/proc/self/exe"); perr == nil {
			unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE, unix.FAN_OPEN_PERM, unix.AT_FDCWD, "/proc/self/exe")
			w.held = true
		} else {
			unix.Close(fd)
			err = perr
		}
	}
	if !w.held {
		fd, err = unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS, fflags)
		if err != nil {
			return nil, fmt.Errorf("fanotify: %w", err)
		}
	}
	w.fd = fd
	if err := unix.Pipe2(w.wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return w, nil
}

// Held reports whether openers are stopped inside their open (permission
// events), or only reported afterwards.
func (w *Watcher) Held() bool { return w.held }

func (w *Watcher) mask() uint64 {
	if w.held {
		return unix.FAN_OPEN_PERM
	}
	return unix.FAN_OPEN
}

// identify opens path without following a link at its end and without
// reading it (O_PATH: that isn't an open as far as fanotify goes), and says
// which file is there. The descriptor is for marking exactly that file.
func identify(path string) (fd int, id fileID, err error) {
	fd, err = unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, id, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, id, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return -1, id, fmt.Errorf("%s isn't an ordinary file", path)
	}
	return fd, fileID{uint64(st.Dev), uint64(st.Ino)}, nil
}

// Watch marks the file that is at path now as the bait path. Marking it
// again changes nothing.
func (w *Watcher) Watch(path string) error {
	fd, id, err := identify(path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("the watcher is closed")
	}
	if cur, ok := w.byPath[path]; ok && cur == id && w.byID[id] == path {
		return nil
	}
	if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_ADD, w.mask(), unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd)); err != nil {
		return fmt.Errorf("watch %s: %w", path, err)
	}
	// (A file that used to be at this path keeps its mark and its entry: if
	// it still exists under another name, opening it is still an open of the
	// bait.)
	w.byID[id], w.byPath[path] = path, id
	if r, err := filepath.EvalSymlinks(path); err == nil {
		w.real[path] = r
	} else {
		w.real[path] = path
	}
	return nil
}

// Watched reports whether the file at path now is marked as that bait.
func (w *Watcher) Watched(path string) bool {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.byID[fileID{uint64(st.Dev), uint64(st.Ino)}] == path
}

// Sync makes files the set of baits: marks what isn't marked (including a
// new file at a known path) and forgets the ones that are no longer baits.
func (w *Watcher) Sync(files []string) (errs []error) {
	want := map[string]bool{}
	for _, f := range files {
		want[f] = true
	}
	w.mu.Lock()
	w.want = len(files)
	for id, p := range w.byID {
		if !want[p] {
			delete(w.byID, id) // its mark goes with the file, or stays unanswered-for: opens are let through
		}
	}
	for p := range w.byPath {
		if !want[p] {
			delete(w.byPath, p)
			delete(w.real, p)
		}
	}
	w.mu.Unlock()
	for _, f := range files {
		if err := w.Watch(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errs
}

// Counts reports how many bait files are marked right now, and how many
// should be.
func (w *Watcher) Counts() (armed, want int) {
	w.mu.Lock()
	paths := make([]string, 0, len(w.byPath))
	for p := range w.byPath {
		paths = append(paths, p)
	}
	want = w.want
	w.mu.Unlock()
	for _, p := range paths {
		if w.Watched(p) {
			armed++
		}
	}
	return armed, want
}

// Close stops Run and lets go of everything. The kernel answers "allow" for
// any opener still waiting.
func (w *Watcher) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.mu.Unlock()
	unix.Write(w.wake[1], []byte{1})
}

func (w *Watcher) logf(format string, args ...any) {
	if w.Logf != nil {
		w.Logf(format, args...)
	}
}

const metaLen = 24 // sizeof(struct fanotify_event_metadata)

// Run reads events until Close. It never blocks on anything but the kernel:
// the service's own opens of a bait (repairing one) are answered right here,
// and everything else is handed to a goroutine.
func (w *Watcher) Run() {
	defer func() {
		unix.Close(w.fd)
		unix.Close(w.wake[0])
		unix.Close(w.wake[1])
	}()
	self := int32(os.Getpid())
	buf := make([]byte, 64*metaLen)
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}, {Fd: int32(w.wake[0]), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			w.logf("fanotify: poll: %v", err)
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			w.logf("fanotify: read: %v", err)
			return
		}
		for off := 0; off+metaLen <= n; {
			ne := binary.NativeEndian
			evLen := int(ne.Uint32(buf[off:]))
			vers := buf[off+4]
			mask := ne.Uint64(buf[off+8:])
			fd := int32(ne.Uint32(buf[off+16:]))
			pid := int32(ne.Uint32(buf[off+20:]))
			if evLen < metaLen {
				break
			}
			off += evLen
			if vers != unix.FANOTIFY_METADATA_VERSION {
				w.logf("fanotify: unexpected event version %d", vers)
				if fd >= 0 {
					w.answer(fd, mask, false)
					unix.Close(int(fd))
				}
				continue
			}
			if mask&unix.FAN_Q_OVERFLOW != 0 {
				w.logf("fanotify: the kernel dropped events (queue overflow)")
			}
			if fd < 0 {
				continue
			}
			w.event(fd, pid, mask, pid == self)
		}
	}
}

// answer tells the kernel whether a held open may go ahead.
func (w *Watcher) answer(fd int32, mask uint64, deny bool) {
	if mask&unix.FAN_OPEN_PERM == 0 {
		return
	}
	var resp [8]byte
	binary.NativeEndian.PutUint32(resp[0:], uint32(fd))
	r := uint32(unix.FAN_ALLOW)
	if deny {
		r = unix.FAN_DENY
	}
	binary.NativeEndian.PutUint32(resp[4:], r)
	if _, err := unix.Write(w.fd, resp[:]); err != nil {
		w.logf("fanotify: answering an open: %v", err)
	}
}

func (w *Watcher) event(fd, pid int32, mask uint64, own bool) {
	var st unix.Stat_t
	bait := ""
	if unix.Fstat(int(fd), &st) == nil {
		w.mu.Lock()
		bait = w.byID[fileID{uint64(st.Dev), uint64(st.Ino)}]
		real := w.real[bait]
		w.mu.Unlock()
		if bait != "" && !own && pid > 0 && w.OnOpen != nil {
			ev := Event{PID: uint32(pid), Path: bait, At: time.Now(), Held: mask&unix.FAN_OPEN_PERM != 0}
			// Reached under another name? Only one that really is this file,
			// here: a container sees the bait under a path of its own, and
			// that's no trick.
			if used, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd))); err == nil && used != real && used != bait {
				var ust unix.Stat_t
				if unix.Lstat(used, &ust) == nil && ust.Dev == st.Dev && ust.Ino == st.Ino {
					ev.Alias = used
				}
			}
			go w.decide(fd, mask, ev)
			return
		}
	}
	// ABA's own open, a file that isn't a bait (any more), or an opener the
	// kernel can't name (another PID namespace's kernel thread): let it go.
	w.answer(fd, mask, false)
	unix.Close(int(fd))
}

func (w *Watcher) decide(fd int32, mask uint64, ev Event) {
	defer unix.Close(int(fd))
	if !ev.Held {
		w.OnOpen(ev)
		return
	}
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				w.logf("PANIC deciding about an open: %v", r)
				done <- false
			}
		}()
		done <- w.OnOpen(ev)
	}()
	deny := false
	select {
	case deny = <-done:
	case <-time.After(w.Timeout):
		if w.TimedOut != nil {
			deny = w.TimedOut(ev)
		}
		w.logf("fanotify: no verdict on pid %d within %v; open %s", ev.PID, w.Timeout, map[bool]string{true: "refused", false: "let through"}[deny])
	}
	w.answer(fd, mask, deny)
}
