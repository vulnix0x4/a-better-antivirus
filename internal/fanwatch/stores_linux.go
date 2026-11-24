package fanwatch

// Watching the real stores for the flight recorder (package recorder).
//
// Unlike a bait, a real store's files are replaced all the time: a browser
// writes "Local State" to a new file and renames it over the old one,
// LevelDB folders make and delete files constantly. A mark on a file goes
// with that file. So the marks are on the folders the files are in, asking
// for opens of anything in them (FAN_EVENT_ON_CHILD): whatever file has the
// name now is covered. Only opens are asked for, never reads (a browser
// reads its databases thousands of times a minute), and nothing is held:
// these are notifications, in a group of their own, and the opener never
// waits.
//
// The kernel hands over a descriptor of each file opened; its name, and the
// opener's PID, are what's reported. The files themselves are marked too, so
// that one opened through a second name it was given elsewhere (a hard link)
// is still reported, under its own path.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// StoreOpen is one open of a file in a watched folder.
type StoreOpen struct {
	Path string
	PID  uint32 // 0 if the kernel couldn't name the opener (another PID namespace)
	At   time.Time
}

// Stores watches the folders of the real stores.
type Stores struct {
	// OnOpen is called for every open by another process, on the reading
	// goroutine: it must be quick.
	OnOpen func(StoreOpen)
	// OnLost is told when the kernel dropped events.
	OnLost func(at time.Time)
	Logf   func(format string, args ...any)

	fd   int
	wake [2]int

	mu     sync.Mutex
	dirs   map[string]bool
	files  map[fileID]string // marked file -> its path when marked
	byPath map[string]fileID
	closed bool
}

const storeMask = unix.FAN_OPEN | unix.FAN_EVENT_ON_CHILD

// NewStores opens the fanotify group for the real stores. It needs root.
func NewStores() (*Stores, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_UNLIMITED_QUEUE|unix.FAN_UNLIMITED_MARKS,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_LARGEFILE|unix.O_NOATIME)
	if err != nil {
		return nil, fmt.Errorf("fanotify: %w", err)
	}
	s := &Stores{fd: fd, dirs: map[string]bool{}, files: map[fileID]string{}, byPath: map[string]fileID{}}
	if err := unix.Pipe2(s.wake[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return s, nil
}

// Sync makes dirs the watched folders and files the marked files. It
// returns, per folder, why it couldn't be watched.
func (s *Stores) Sync(dirs, files []string) map[string]error {
	failed := map[string]error{}
	want := map[string]bool{}
	for _, d := range dirs {
		want[d] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		for _, d := range dirs {
			failed[d] = errors.New("the watcher is closed")
		}
		return failed
	}
	for d := range s.dirs {
		if !want[d] {
			unix.FanotifyMark(s.fd, unix.FAN_MARK_REMOVE|unix.FAN_MARK_ONLYDIR, storeMask, unix.AT_FDCWD, d)
			delete(s.dirs, d)
		}
	}
	for _, d := range dirs {
		// Marked again every time: a folder deleted and made again under the
		// same name is a new folder, without the mark.
		if err := unix.FanotifyMark(s.fd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR, storeMask, unix.AT_FDCWD, d); err != nil {
			failed[d] = err
			delete(s.dirs, d)
			continue
		}
		s.dirs[d] = true
	}
	keep := map[string]bool{}
	for _, f := range files {
		keep[f] = true
		fd, id, err := identify(f)
		if err != nil {
			continue
		}
		if unix.FanotifyMark(s.fd, unix.FAN_MARK_ADD, unix.FAN_OPEN, unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd)) == nil {
			if old, ok := s.byPath[f]; ok && old != id {
				delete(s.files, old)
			}
			s.files[id], s.byPath[f] = f, id
		}
		unix.Close(fd)
	}
	for p, id := range s.byPath {
		if !keep[p] {
			delete(s.byPath, p)
			delete(s.files, id)
		}
	}
	return failed
}

// Close stops Run.
func (s *Stores) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	unix.Write(s.wake[1], []byte{1})
}

func (s *Stores) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Run reads events until Close.
func (s *Stores) Run() {
	defer func() {
		unix.Close(s.fd)
		unix.Close(s.wake[0])
		unix.Close(s.wake[1])
	}()
	self := int32(os.Getpid())
	buf := make([]byte, 256*metaLen)
	fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}, {Fd: int32(s.wake[0]), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			s.logf("fanotify (stores): poll: %v", err)
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		n, err := unix.Read(s.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			s.logf("fanotify (stores): read: %v", err)
			return
		}
		now := time.Now()
		ne := binary.NativeEndian
		for off := 0; off+metaLen <= n; {
			evLen := int(ne.Uint32(buf[off:]))
			if evLen < metaLen || off+evLen > n {
				break
			}
			mask := ne.Uint64(buf[off+8:])
			fd := int32(ne.Uint32(buf[off+16:]))
			pid := int32(ne.Uint32(buf[off+20:]))
			off += evLen
			if mask&unix.FAN_Q_OVERFLOW != 0 && s.OnLost != nil {
				s.OnLost(now)
			}
			if fd < 0 {
				continue
			}
			if pid != self && s.OnOpen != nil {
				if p := s.pathOf(int(fd)); p != "" {
					op := StoreOpen{Path: p, At: now}
					if pid > 0 {
						op.PID = uint32(pid)
					}
					s.OnOpen(op)
				}
			}
			unix.Close(int(fd))
		}
	}
}

// pathOf is the path of the file an event's descriptor is open on: the name
// it was opened by, or, when that isn't one of the marked files' (a second
// name made elsewhere), the marked file's own.
func (s *Stores) pathOf(fd int) string {
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return ""
	}
	s.mu.Lock()
	_, known := s.byPath[p]
	s.mu.Unlock()
	if known {
		return p
	}
	if id, _, ok := idOf(fd, ""); ok {
		s.mu.Lock()
		own := s.files[id]
		s.mu.Unlock()
		if own != "" {
			return own
		}
	}
	return p
}
