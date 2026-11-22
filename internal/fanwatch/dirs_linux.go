package fanwatch

// Watching the folders the baits are in.
//
// The mark on a bait file says when it's opened, not when it's deleted,
// renamed away or replaced (a rename over it): that's a change to the folder,
// not to the file. So the folders get marks of their own, in a second
// fanotify group that reports names (FAN_REPORT_DFID_NAME, Linux 5.9): the
// kernel says which folder, which name, what happened and which process did
// it. The folders above a bait count too, up to the home folder it's in:
// moving ~/.config/vivaldi away takes its baits with it.
//
// It only notices; nothing is held. The service puts the bait back right
// away and reports whoever did it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Change is a bait (or a folder holding baits) gone from its place.
type Change struct {
	PID   uint32
	Path  string   // the name that went: a bait, or a folder above some
	Baits []string // the baits it takes with it
	What  string   // "deleted", "renamed away", "replaced"
	At    time.Time
}

// Dirs watches the folders of a set of baits.
type Dirs struct {
	// OnChange is called for every change that takes a bait with it, by a
	// process other than this one, in a goroutine of its own.
	OnChange func(c Change)
	Logf     func(format string, args ...any)

	fd   int
	wake [2]int

	mu     sync.Mutex
	byDir  map[string]string // file handle (type + bytes) -> folder
	marked map[string]bool   // folder -> marked
	baits  map[string]bool
	closed bool
}

const dirMask = unix.FAN_DELETE | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO | unix.FAN_ONDIR

// NewDirs opens the fanotify group for folders. It needs root and Linux 5.9.
func NewDirs() (*Dirs, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fanotify for folders (Linux 5.9 or later): %w", err)
	}
	d := &Dirs{fd: fd, byDir: map[string]string{}, marked: map[string]bool{}, baits: map[string]bool{}}
	if err := unix.Pipe2(d.wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return d, nil
}

func handleKey(htype int32, b []byte) string { return fmt.Sprintf("%d:%x", htype, b) }

func dirHandle(dir string) (string, error) {
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, unix.AT_SYMLINK_FOLLOW)
	if err != nil {
		return "", err
	}
	return handleKey(h.Type(), h.Bytes()), nil
}

// folders are the ones to watch for bait: its own, and those above it up to
// and including home (only its own if it isn't in home).
func folders(bait, home string) []string {
	dir := filepath.Dir(bait)
	out := []string{dir}
	if home == "" || !strings.HasPrefix(dir+"/", strings.TrimSuffix(home, "/")+"/") {
		return out
	}
	for d := dir; d != home && len(d) > len(home); {
		d = filepath.Dir(d)
		out = append(out, d)
	}
	return out
}

// Sync makes baits the set of files whose folders are watched; home is the
// folder above which nothing more is marked.
func (d *Dirs) Sync(baits []string, home string) (errs []error) {
	want := map[string]bool{}
	for _, b := range baits {
		for _, f := range folders(b, home) {
			want[f] = true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.baits = map[string]bool{}
	for _, b := range baits {
		d.baits[b] = true
	}
	for dir := range want {
		h, err := dirHandle(dir)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("watch folder %s: %w", dir, err))
			}
			continue
		}
		if d.byDir[h] == dir && d.marked[dir] {
			continue
		}
		// The folder may be a new one under an old name: mark what's there now.
		if err := unix.FanotifyMark(d.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_DONT_FOLLOW|unix.FAN_MARK_ONLYDIR, dirMask, unix.AT_FDCWD, dir); err != nil {
			errs = append(errs, fmt.Errorf("watch folder %s: %w", dir, err))
			continue
		}
		d.byDir[h], d.marked[dir] = dir, true
	}
	for dir := range d.marked {
		if !want[dir] {
			unix.FanotifyMark(d.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_DONT_FOLLOW|unix.FAN_MARK_ONLYDIR, dirMask, unix.AT_FDCWD, dir)
			delete(d.marked, dir)
			for h, x := range d.byDir {
				if x == dir {
					delete(d.byDir, h)
				}
			}
		}
	}
	return errs
}

// Close stops Run.
func (d *Dirs) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	d.mu.Unlock()
	unix.Write(d.wake[1], []byte{1})
}

func (d *Dirs) logf(format string, args ...any) {
	if d.Logf != nil {
		d.Logf(format, args...)
	}
}

// Run reads events until Close.
func (d *Dirs) Run() {
	defer func() {
		unix.Close(d.fd)
		unix.Close(d.wake[0])
		unix.Close(d.wake[1])
	}()
	self := int32(os.Getpid())
	buf := make([]byte, 64<<10)
	fds := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}, {Fd: int32(d.wake[0]), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			d.logf("fanotify (folders): poll: %v", err)
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		n, err := unix.Read(d.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			d.logf("fanotify (folders): read: %v", err)
			return
		}
		ne := binary.NativeEndian
		for off := 0; off+metaLen <= n; {
			evLen := int(ne.Uint32(buf[off:]))
			if evLen < metaLen || off+evLen > n {
				break
			}
			mask := ne.Uint64(buf[off+8:])
			pid := int32(ne.Uint32(buf[off+20:]))
			ev := buf[off : off+evLen]
			off += evLen
			if mask&unix.FAN_Q_OVERFLOW != 0 {
				d.logf("fanotify (folders): the kernel dropped events (queue overflow)")
				continue
			}
			if pid == self {
				continue // ABA repairing or removing its own baits
			}
			dir, name, h, ok := d.parse(ev[metaLen:])
			if !ok {
				continue
			}
			// A folder that was moved away keeps its mark: what happens in it
			// now happens elsewhere, not at the path it was marked under.
			if cur, err := dirHandle(dir); err != nil || cur != h {
				d.mu.Lock()
				if d.byDir[h] == dir {
					delete(d.byDir, h)
					delete(d.marked, dir)
				}
				d.mu.Unlock()
				continue
			}
			d.changed(uint32(pid), filepath.Join(dir, name), mask)
		}
	}
}

// parse reads the DFID_NAME record of an event: the folder's file handle and
// the name in it.
func (d *Dirs) parse(info []byte) (dir, name, handle string, ok bool) {
	ne := binary.NativeEndian
	for len(info) >= 4 {
		typ, size := info[0], int(ne.Uint16(info[2:]))
		if size < 4 || size > len(info) {
			return "", "", "", false
		}
		rec := info[:size]
		info = info[size:]
		if typ != unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
			continue
		}
		// header (4), fsid (8), handle_bytes (4), handle_type (4), handle, name\0
		if len(rec) < 20 {
			return "", "", "", false
		}
		hb := int(ne.Uint32(rec[12:]))
		ht := int32(ne.Uint32(rec[16:]))
		if 20+hb > len(rec) {
			return "", "", "", false
		}
		h := handleKey(ht, rec[20:20+hb])
		rest := rec[20+hb:]
		if i := strings.IndexByte(string(rest), 0); i >= 0 {
			rest = rest[:i]
		}
		d.mu.Lock()
		dir = d.byDir[h]
		d.mu.Unlock()
		return dir, string(rest), h, dir != "" && len(rest) > 0
	}
	return "", "", "", false
}

func (d *Dirs) changed(pid uint32, path string, mask uint64) {
	d.mu.Lock()
	var hit []string
	for b := range d.baits {
		if b == path || strings.HasPrefix(b, path+"/") {
			hit = append(hit, b)
		}
	}
	d.mu.Unlock()
	if len(hit) == 0 || d.OnChange == nil {
		return
	}
	what := "deleted"
	switch {
	case mask&unix.FAN_MOVED_TO != 0:
		what = "replaced"
	case mask&unix.FAN_MOVED_FROM != 0:
		what = "renamed away"
	}
	go d.OnChange(Change{PID: pid, Path: path, Baits: hit, What: what, At: time.Now()})
}
