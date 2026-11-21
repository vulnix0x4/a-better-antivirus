package procinfo

// Freezing on Linux.
//
// Stopping a process with a signal (SIGSTOP) isn't enough: any other program
// running as the same user can send SIGCONT, so a stealer with a second
// process un-freezes itself in one call. Instead ABA moves the process into a
// control group of its own that the kernel keeps frozen (cgroup v2's
// freezer). That group belongs to root, and it sits at the top of the cgroup
// tree: to move a process out of it, a program needs write access to the
// tree's root, which only root has. So nothing running as you can thaw what
// ABA froze. The kernel freezes every thread of the process before it runs
// another instruction, and a process frozen while it is still inside the
// open() of a bait never gets to use what that open returns.
//
// Unlike a Windows job object, the group outlives the service: what's frozen
// stays frozen, locked, across a restart, a crash or an update of ABA. "Hold"
// therefore only records what this service is responsible for.
//
// Where each process came from is noted in a root-only folder under /run, so
// the CLI (`aba resume`, `aba release`), which runs as root itself, can put it
// back where it was.
//
// Machines without a usable cgroup v2 tree: on a "hybrid" system the v2 tree
// is there, without controllers, and the freezer needs none. Where no v2 tree
// is mounted at all, ABA mounts one for itself. Only a kernel older than 5.2
// has no v2 freezer; there ABA falls back to SIGSTOP, and Hold reports that
// the freeze isn't tamper-proof.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// holdGroup is the frozen control group's name, at the top of the tree.
const holdGroup = "file-access-monitor.frozen"

var (
	fzMu   sync.Mutex
	fzRoot string // where the cgroup v2 tree is mounted
	fzDir  string // the frozen group
	fzErr  error
	fzAt   time.Time
)

// cgroupRoot finds the cgroup v2 tree, mounting one if the system has none.
func cgroupRoot() (string, error) {
	best := ""
	for _, line := range readLines("/proc/self/mountinfo") {
		i := strings.Index(line, " - ")
		f := strings.Fields(line)
		if i < 0 || len(f) < 5 {
			continue
		}
		if t := strings.Fields(line[i+3:]); len(t) == 0 || t[0] != "cgroup2" {
			continue
		}
		// The whole tree, not a part of it bound somewhere.
		if f[3] != "/" {
			continue
		}
		p := unescape(f[4])
		if p == "/sys/fs/cgroup" {
			return p, nil
		}
		if best == "" {
			best = p
		}
	}
	if best != "" {
		return best, nil
	}
	own := filepath.Join(paths.RunDir(), "cgroup2")
	if err := os.MkdirAll(own, 0o700); err != nil {
		return "", err
	}
	if err := unix.Mount("none", own, "cgroup2", 0, ""); err != nil {
		return "", fmt.Errorf("no cgroup v2 tree here, and mounting one failed: %w", err)
	}
	return own, nil
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// freezer returns the frozen group's folder, making it if need be.
func freezer() (string, error) {
	fzMu.Lock()
	defer fzMu.Unlock()
	if fzDir != "" {
		return fzDir, nil
	}
	if fzErr != nil && time.Since(fzAt) < time.Minute {
		return "", fzErr
	}
	fzAt = time.Now()
	root, err := cgroupRoot()
	if err != nil {
		fzErr = err
		return "", err
	}
	dir := filepath.Join(root, holdGroup)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		fzErr = fmt.Errorf("make the frozen group: %w", err)
		return "", fzErr
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("1"), 0o644); err != nil {
		os.Remove(dir)
		fzErr = fmt.Errorf("this kernel has no cgroup v2 freezer: %w", err)
		return "", fzErr
	}
	fzRoot, fzDir, fzErr = root, dir, nil
	return dir, nil
}

// FreezerStatus says whether ABA can lock a process frozen on this machine,
// and if not, why.
func FreezerStatus() error {
	_, err := freezer()
	return err
}

// RemoveFreezer takes the frozen group away again (uninstall). Whatever is
// still in it is let go first: back where it came from, running.
func RemoveFreezer() error {
	fzMu.Lock()
	dir := fzDir
	fzMu.Unlock()
	if dir == "" {
		root, err := cgroupRoot()
		if err != nil {
			return nil
		}
		dir = filepath.Join(root, holdGroup)
	}
	if _, err := os.Stat(dir); err != nil {
		os.RemoveAll(originDir())
		return nil
	}
	for _, line := range readLines(filepath.Join(dir, "cgroup.procs")) {
		if pid, err := strconv.ParseUint(strings.TrimSpace(line), 10, 32); err == nil {
			Resume(uint32(pid))
		}
	}
	os.RemoveAll(originDir())
	var err error
	for try := 0; try < 20; try++ { // a group goes once the last process has left it
		if err = os.Remove(dir); err == nil || errors.Is(err, os.ErrNotExist) {
			err = nil
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	fzMu.Lock()
	fzDir = ""
	fzMu.Unlock()
	return err
}

// cgroupOf returns the v2 control group a process is in ("/user.slice/…").
func cgroupOf(pid uint32) string {
	for _, line := range readLines(fmt.Sprintf("/proc/%d/cgroup", pid)) {
		if strings.HasPrefix(line, "0::") {
			return line[3:]
		}
	}
	return ""
}

// Frozen reports whether pid is in ABA's frozen group right now.
func Frozen(pid uint32) bool { return cgroupOf(pid) == "/"+holdGroup }

// ---- where a frozen process came from ----

const stoppedOnly = "!stopped" // frozen with SIGSTOP: there was no freezer

func originDir() string { return filepath.Join(paths.RunDir(), "frozen") }

func originFile(pid uint32, ct int64) string {
	return filepath.Join(originDir(), HoldName(pid, ct))
}

func saveOrigin(pid uint32, ct int64, origin string) error {
	if err := os.MkdirAll(originDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(originFile(pid, ct), []byte(origin), 0o600)
}

func loadOrigin(pid uint32, ct int64) (string, bool) {
	b, err := os.ReadFile(originFile(pid, ct))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// ---- freezing ----

// Suspend freezes a process: every thread of it, before it runs another
// instruction. Freezing one that's frozen already changes nothing.
func Suspend(pid uint32) error {
	if systemPID(pid) || pid == uint32(os.Getpid()) {
		return fmt.Errorf("refusing to freeze pid %d", pid)
	}
	ct, err := CreateTime(pid)
	if err != nil {
		return err
	}
	dir, ferr := freezer()
	if ferr != nil {
		if err := unix.Kill(int(pid), unix.SIGSTOP); err != nil {
			return err
		}
		return saveOrigin(pid, ct, stoppedOnly)
	}
	cur := cgroupOf(pid)
	if cur == "/"+holdGroup {
		return nil
	}
	if err := saveOrigin(pid, ct, cur); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(int(pid))), 0o644); err != nil {
		os.Remove(originFile(pid, ct))
		return fmt.Errorf("freeze pid %d: %w", pid, err)
	}
	return nil
}

// Resume lets a frozen process run again, back in the control group it came
// from. (Root only: the CLI does this itself.)
func Resume(pid uint32) error {
	ct, err := CreateTime(pid)
	if err != nil {
		return err
	}
	origin, known := loadOrigin(pid, ct)
	// Off the record first: from here on, the process leaving the frozen
	// group is ABA's doing, not an escape (see Escaped).
	os.Remove(originFile(pid, ct))
	if known && origin == stoppedOnly {
		return unix.Kill(int(pid), unix.SIGCONT)
	}
	if !Frozen(pid) {
		return nil
	}
	root, err := cgroupRoot()
	if err != nil {
		return err
	}
	if !known || origin == "" || !strings.HasPrefix(origin, "/") {
		origin = "/"
	}
	// Its own group may be gone by now (systemd removes a scope once the last
	// process has left it): make it again if its parent is still there,
	// otherwise the nearest group above that takes processes.
	os.Mkdir(filepath.Join(root, origin), 0o755)
	var last error
	for g := origin; ; g = filepath.Dir(g) {
		last = os.WriteFile(filepath.Join(root, g, "cgroup.procs"), []byte(strconv.Itoa(int(pid))), 0o644)
		if last == nil {
			return nil
		}
		if g == "/" || g == "." {
			break
		}
	}
	return fmt.Errorf("unfreeze pid %d: %w", pid, last)
}

// Kill terminates a process (a frozen one too).
func Kill(pid uint32) error {
	if systemPID(pid) || pid == uint32(os.Getpid()) {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	ct, _ := CreateTime(pid)
	if err := unix.Kill(int(pid), unix.SIGKILL); err != nil {
		return err
	}
	if ct != 0 {
		os.Remove(originFile(pid, ct))
	}
	return nil
}

// ---- holds ----

var (
	holdMu sync.Mutex
	holds  = map[string]hold{} // HoldName -> what this service holds
)

type hold struct {
	pid uint32
	ct  int64
	at  time.Time
}

// Hold locks a frozen process frozen, so that no other program running as the
// same user can let it run again. On Linux the freeze is that lock already
// (see the top of this file); Hold checks it and takes responsibility for the
// process. It fails where there is no freezer: the process is then only
// stopped, which a program of the same user could undo.
func Hold(pid uint32, createTime int64) error {
	if !Alive(pid, createTime) {
		return fmt.Errorf("pid %d is gone", pid)
	}
	if !Frozen(pid) {
		if err := FreezerStatus(); err != nil {
			return fmt.Errorf("pid %d is only stopped, not locked frozen: %v", pid, err)
		}
		if err := Suspend(pid); err != nil {
			return err
		}
	}
	holdMu.Lock()
	holds[HoldName(pid, createTime)] = hold{pid: pid, ct: createTime, at: time.Now()}
	holdMu.Unlock()
	return nil
}

// Unhold releases this process's hold on pid, if it has one. The process
// stays frozen (Resume lifts that).
func Unhold(pid uint32, createTime int64) {
	holdMu.Lock()
	delete(holds, HoldName(pid, createTime))
	holdMu.Unlock()
}

// Held reports how many processes this process holds.
func Held() int {
	holdMu.Lock()
	defer holdMu.Unlock()
	return len(holds)
}

// DropHolds lets go of the holds made before madeBefore that keep (given a
// HoldName) no longer wants. It never kills or thaws anything: what's frozen
// stays in the frozen group until Resume takes it out.
func DropHolds(madeBefore time.Time, keep func(name string) bool) {
	holdMu.Lock()
	defer holdMu.Unlock()
	for name, h := range holds {
		if h.at.Before(madeBefore) && !keep(name) {
			delete(holds, name)
		}
	}
}

// Escaped finds held processes that are no longer in the frozen group
// although nobody released them, puts them back, and returns them.
//
// Nothing running as you can move a process out of the group by itself. But
// the system's service manager runs as root and moves processes between
// groups on request, in some cases for the user they belong to. Should a
// frozen process get out that way, this is what notices: the record of where
// it came from is still there (Resume removes it first), and it isn't frozen.
func Escaped() []uint32 {
	holdMu.Lock()
	var check []hold
	for _, h := range holds {
		check = append(check, h)
	}
	holdMu.Unlock()
	var out []uint32
	for _, h := range check {
		if !Alive(h.pid, h.ct) || Frozen(h.pid) {
			continue
		}
		origin, known := loadOrigin(h.pid, h.ct)
		if !known || origin == stoppedOnly {
			continue // released by the CLI a moment ago, or never in the group
		}
		dir, err := freezer()
		if err != nil {
			continue
		}
		if os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(int(h.pid))), 0o644) == nil {
			out = append(out, h.pid)
		}
	}
	return out
}
