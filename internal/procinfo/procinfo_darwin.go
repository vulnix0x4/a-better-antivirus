package procinfo

// Processes on macOS, read from the kernel (sysctl and proc_info, the calls
// ps and Activity Monitor use). No cgo.
//
// Freezing uses pid_suspend, a private call that only root may make. What it
// suspends stays suspended until root calls pid_resume: a SIGCONT does nothing
// to it, and the process's own user can't call pid_resume. Measured on macOS
// 15 and 26: 20 of 20 test programs stayed frozen through their own user's
// SIGCONT. It also outlives the service: a program frozen this way stays
// frozen if ABA's service stops, until `aba resume` or `aba kill`.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ---- the kernel's own process record ----

func kinfo(pid uint32) (*unix.KinfoProc, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return nil, fmt.Errorf("process %d: %w", pid, err)
	}
	if k.Proc.P_pid != int32(pid) {
		return nil, fmt.Errorf("no process %d (the kernel answered for %d)", pid, k.Proc.P_pid)
	}
	return k, nil
}

// SZOMB: exited, not yet collected by its parent.
const szomb = 5

func startOf(k *unix.KinfoProc) int64 {
	return k.Proc.P_starttime.Sec*1_000_000 + int64(k.Proc.P_starttime.Usec)
}

func commOf(k *unix.KinfoProc) string {
	c := k.Proc.P_comm[:]
	if i := bytes.IndexByte(c, 0); i >= 0 {
		c = c[:i]
	}
	return string(c)
}

// ---- looking at processes ----

// Snapshot lists all processes.
func Snapshot() (map[uint32]Entry, error) {
	ks, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]Entry, len(ks))
	for i := range ks {
		k := &ks[i]
		if k.Proc.P_stat == szomb || k.Proc.P_pid < 0 {
			continue
		}
		pid := uint32(k.Proc.P_pid)
		out[pid] = Entry{PID: pid, PPID: uint32(k.Eproc.Ppid), Exe: commOf(k), CreateTime: startOf(k)}
	}
	return out, nil
}

// CreateTime says when a process started, in microseconds since 1970 (see
// Entry.CreateTime). Together with the PID it identifies a process for good.
func CreateTime(pid uint32) (int64, error) {
	k, err := kinfo(pid)
	if err != nil {
		return 0, err
	}
	if k.Proc.P_stat == szomb {
		return 0, fmt.Errorf("process %d has exited", pid)
	}
	return startOf(k), nil
}

// proc_info(2): what libproc's proc_pidpath and proc_pidinfo call.
const (
	procInfoCallPidinfo   = 2
	procInfoCallPidfdinfo = 3

	procPidVnodePathInfo   = 9  // the working folder
	procPidPathInfo        = 11 // the executable
	procPidFdVnodePathInfo = 2  // what an open file descriptor is

	vnodeInfoSize = 152  // struct vnode_info
	maxPath       = 1024 // MAXPATHLEN
)

func procInfo(call, pid, flavor int, arg uint64, buf []byte) (int, error) {
	n, _, e := syscall.Syscall6(unix.SYS_PROC_INFO, uintptr(call), uintptr(pid), uintptr(flavor),
		uintptr(arg), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ImagePath returns the full path of the process executable: the file the
// kernel is running, whatever the process calls itself.
func ImagePath(pid uint32) (string, error) {
	if pid == 0 {
		return "", errors.New("the kernel has no executable")
	}
	buf := make([]byte, 4*maxPath)
	if _, err := procInfo(procInfoCallPidinfo, int(pid), procPidPathInfo, 0, buf); err != nil {
		if r, ok := Recent(pid); ok {
			return r.Image, nil
		}
		return "", err
	}
	p := cstring(buf)
	if p == "" {
		return "", fmt.Errorf("no executable for pid %d", pid)
	}
	return p, nil
}

// Args returns a process's arguments as it was started with them. Only root
// (or the process's own user) may read them.
func Args(pid uint32) ([]string, error) {
	b, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(b) < 4 {
		if r, ok := Recent(pid); ok && len(r.Args) > 0 {
			return r.Args, nil
		}
		if err == nil {
			err = errors.New("no arguments")
		}
		return nil, err
	}
	return parseProcArgs(b)
}

// parseProcArgs reads kern.procargs2: argc, the executable's path, padding,
// then argc strings (and the environment, which ABA doesn't read).
func parseProcArgs(b []byte) ([]string, error) {
	if len(b) < 4 {
		return nil, errors.New("short procargs")
	}
	argc := int(binary.LittleEndian.Uint32(b[:4]))
	rest := b[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return nil, errors.New("unreadable procargs")
	}
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	var args []string
	for len(args) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			args = append(args, string(rest))
			break
		}
		args = append(args, string(rest[:j]))
		rest = rest[j+1:]
	}
	return args, nil
}

// CommandLine returns the process command line, the way you'd type it.
func CommandLine(pid uint32) (string, error) {
	args, err := Args(pid)
	if err != nil {
		return "", err
	}
	return JoinArgs(args), nil
}

// JoinArgs writes arguments as one command line, quoting what needs it.
func JoinArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`|&;<>()*?[]{}!#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		q[i] = a
	}
	return strings.Join(q, " ")
}

// Alive reports whether pid exists and (if createTime != 0) is the same process.
func Alive(pid uint32, createTime int64) bool {
	ct, err := CreateTime(pid)
	if err != nil {
		return false
	}
	return createTime == 0 || ct == createTime
}

// RunningImage lists the processes running the executable at path.
func RunningImage(path string) []uint32 {
	snap, err := Snapshot()
	if err != nil {
		return nil
	}
	base := filepath.Base(path)
	var out []uint32
	for pid, e := range snap {
		// The kernel's short name is the file name cut to 16 characters: a
		// cheap first sieve before asking for the full path.
		if !strings.HasPrefix(base, e.Exe) {
			continue
		}
		if img, err := ImagePath(pid); err == nil && strings.EqualFold(img, path) {
			out = append(out, pid)
		}
	}
	return out
}

// BaseName is the file name of a program's path, for display.
func BaseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

// systemPID reports whether pid is one ABA must never touch whatever it is:
// the kernel (0) and launchd (1).
func systemPID(pid uint32) bool { return pid <= 1 }

// ---- who a process runs as ----

func uidOf(pid uint32) (uint32, error) {
	k, err := kinfo(pid)
	if err != nil {
		return 0, err
	}
	return k.Eproc.Ucred.Uid, nil
}

// SelfElevated reports whether this process has administrator (root) rights.
func SelfElevated() bool { return os.Geteuid() == 0 }

// Elevated reports whether pid runs with root's rights (its effective user is
// root). When it can't tell it says yes: ABA is careful with those.
func Elevated(pid uint32) bool {
	k, err := kinfo(pid)
	if err != nil {
		return true
	}
	return k.Eproc.Ucred.Uid == 0 || k.Eproc.Pcred.P_ruid == 0
}

// person reports whether uid is a person's account: macOS gives the first one
// 501, and keeps the ones below 500 (and nobody's, -2) for the system.
func person(uid uint32) bool { return uid >= 500 && uid < 1<<31 }

// UserSession reports whether pid is an ordinary user's program rather than
// a system service.
func UserSession(pid uint32) bool {
	uid, err := uidOf(pid)
	return err == nil && person(uid)
}

// UserID returns the account a process runs as: its numeric user ID.
func UserID(pid uint32) (string, error) {
	uid, err := uidOf(pid)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(uid), 10), nil
}

// ServiceAccount reports whether the account with this ID is one that system
// services run as (root, the _-named accounts below 500, nobody), not a person.
func ServiceAccount(id string) bool {
	uid, err := strconv.ParseUint(id, 10, 32)
	return err == nil && !person(uint32(uid))
}

// TTY returns the terminal a process is controlled from (0: none).
func TTY(pid uint32) int {
	k, err := kinfo(pid)
	if err != nil || k.Eproc.Tdev == -1 {
		return 0
	}
	return int(k.Eproc.Tdev)
}

// ParentPID returns the process that started pid (0 if unknown).
func ParentPID(pid uint32) uint32 {
	k, err := kinfo(pid)
	if err != nil {
		if r, ok := Recent(pid); ok {
			return r.PPID
		}
		return 0
	}
	return uint32(k.Eproc.Ppid)
}

// Cwd returns the folder a process is working in ("" if it can't be seen).
func Cwd(pid uint32) string {
	buf := make([]byte, 2*(vnodeInfoSize+maxPath))
	if _, err := procInfo(procInfoCallPidinfo, int(pid), procPidVnodePathInfo, 0, buf); err != nil {
		if r, ok := Recent(pid); ok {
			return r.Cwd
		}
		return ""
	}
	return cstring(buf[vnodeInfoSize : vnodeInfoSize+maxPath])
}

// Stdin says which file a process reads its input from: a path such as
// /dev/ttys003 for a terminal, "" when it's a pipe, a socket or nothing.
func Stdin(pid uint32) string {
	const fileInfoSize = 24 // struct proc_fileinfo
	buf := make([]byte, fileInfoSize+vnodeInfoSize+maxPath)
	if _, err := procInfo(procInfoCallPidfdinfo, int(pid), procPidFdVnodePathInfo, 0, buf); err != nil {
		if r, ok := Recent(pid); ok {
			return r.Stdin
		}
		return ""
	}
	return cstring(buf[fileInfoSize+vnodeInfoSize:])
}

// ---- processes that have exited ----

// A short-lived reader (cat, a shell running one line) is usually gone by the
// time the engine asks about it, and so is what started it. The watcher
// writes down what it learns about each process as it starts (Remember);
// ImagePath, Args, ParentPID, Cwd and Stdin fall back on that once the
// process itself is gone.

// RecentProcess is what was seen of a process while it ran.
type RecentProcess struct {
	PID   uint32
	PPID  uint32
	Image string
	Args  []string
	Cwd   string
	Stdin string
	// Signing facts from the kernel, as the watcher reported them.
	Platform bool   // part of macOS
	TeamID   string // the developer's team ("" for Apple's and unsigned code)
	SignID   string
	CSFlags  uint32
	at       time.Time
}

const recentFor = 2 * time.Minute

var (
	recentMu sync.Mutex
	recent   = map[uint32]RecentProcess{}
)

// Remember keeps what was seen of a process for a couple of minutes.
func Remember(p RecentProcess) {
	if p.PID == 0 {
		return
	}
	p.at = time.Now()
	recentMu.Lock()
	defer recentMu.Unlock()
	if len(recent) > 4096 {
		for k, v := range recent {
			if time.Since(v.at) > recentFor {
				delete(recent, k)
			}
		}
	}
	if old, ok := recent[p.PID]; ok && old.Image == p.Image {
		// Fill in what the newer report doesn't say.
		if len(p.Args) == 0 {
			p.Args = old.Args
		}
		if p.Cwd == "" {
			p.Cwd = old.Cwd
		}
		if p.Stdin == "" {
			p.Stdin = old.Stdin
		}
		if p.PPID == 0 {
			p.PPID = old.PPID
		}
	}
	recent[p.PID] = p
}

// Recent returns what was seen of pid lately. While pid is running, only if
// it's the same program (a reused PID is somebody else).
func Recent(pid uint32) (RecentProcess, bool) {
	recentMu.Lock()
	r, ok := recent[pid]
	recentMu.Unlock()
	if !ok || time.Since(r.at) > recentFor {
		return RecentProcess{}, false
	}
	return r, true
}

// ---- freezing ----

func pidCall(num uintptr, pid uint32, arg uintptr) error {
	if _, _, e := syscall.Syscall(num, uintptr(pid), arg, 0); e != 0 {
		return e
	}
	return nil
}

var errFrozenAlready = errors.New("it's frozen already")

var (
	frozenMu sync.Mutex
	frozen   = map[uint32]int64{} // pid -> create time, what this process froze
)

// Suspend freezes a process with pid_suspend: only root can let it run again.
func Suspend(pid uint32) error {
	if systemPID(pid) || pid == uint32(os.Getpid()) {
		return fmt.Errorf("refusing to freeze pid %d", pid)
	}
	ct, err := CreateTime(pid)
	if err != nil {
		return err
	}
	frozenMu.Lock()
	defer frozenMu.Unlock()
	if t, ok := frozen[pid]; ok && t == ct {
		return errFrozenAlready
	}
	if err := pidCall(unix.SYS_PID_SUSPEND, pid, 0); err != nil {
		return fmt.Errorf("freeze pid %d: %w", pid, err)
	}
	frozen[pid] = ct
	return nil
}

// Resume lets a frozen process run again (pid_resume; root only). A process
// that isn't suspended is left as it is.
func Resume(pid uint32) error {
	frozenMu.Lock()
	delete(frozen, pid)
	frozenMu.Unlock()
	if _, err := CreateTime(pid); err != nil {
		return err
	}
	if err := pidCall(unix.SYS_PID_RESUME, pid, 0); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("unfreeze pid %d: %w", pid, err)
	}
	// One SIGCONT too, in case it was stopped as well: a frozen program
	// shouldn't stay stopped once the person let it go.
	unix.Kill(int(pid), unix.SIGCONT)
	return nil
}

// Kill terminates a process. A suspended one has to run again for a moment
// to die, so it's told to die first and then let go: the kill is the first
// thing it does.
func Kill(pid uint32) error {
	if systemPID(pid) || pid == uint32(os.Getpid()) {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	if err := unix.Kill(int(pid), unix.SIGKILL); err != nil {
		return err
	}
	frozenMu.Lock()
	delete(frozen, pid)
	frozenMu.Unlock()
	pidCall(unix.SYS_PID_RESUME, pid, 0)
	return nil
}

var (
	holdMu sync.Mutex
	holds  = map[string]hold{}
)

type hold struct {
	pid uint32
	ct  int64
	at  time.Time
}

// Hold locks a frozen process frozen, so that no other program running as
// the same user can let it run again. pid_suspend already does that, so this
// only makes sure it's suspended and keeps count.
func Hold(pid uint32, createTime int64) error {
	if !Alive(pid, createTime) {
		return fmt.Errorf("pid %d is gone", pid)
	}
	frozenMu.Lock()
	_, mine := frozen[pid]
	frozenMu.Unlock()
	if !mine {
		if err := Suspend(pid); err != nil && !errors.Is(err, errFrozenAlready) {
			return err
		}
	}
	holdMu.Lock()
	holds[HoldName(pid, createTime)] = hold{pid: pid, ct: createTime, at: time.Now()}
	holdMu.Unlock()
	return nil
}

// Unhold forgets this process's hold on pid (it stays suspended: Resume lets
// it go).
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

// DropHolds forgets the holds made before madeBefore that keep (given a
// HoldName) no longer wants. It never kills or resumes anything.
func DropHolds(madeBefore time.Time, keep func(name string) bool) {
	holdMu.Lock()
	defer holdMu.Unlock()
	for name, h := range holds {
		if h.at.Before(madeBefore) && !keep(name) {
			delete(holds, name)
		}
	}
}

// ---- network ----

// ShutdownSockets closes every connection pid has open (pid_shutdown_sockets,
// root only). Measured: a live TLS connection went from ESTABLISHED to CLOSED.
func ShutdownSockets(pid uint32) error {
	const disconnectAll = 2 // SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL
	if systemPID(pid) || pid == uint32(os.Getpid()) {
		return fmt.Errorf("refusing to touch pid %d", pid)
	}
	return pidCall(unix.SYS_PID_SHUTDOWN_SOCKETS, pid, disconnectAll)
}

// ---- forensics ----

// Connections lists the sockets the given processes have open (from lsof).
func Connections(pids []uint32) ([]Conn, error) {
	if len(pids) == 0 {
		return nil, nil
	}
	list := make([]string, len(pids))
	for i, p := range pids {
		list[i] = strconv.FormatUint(uint64(p), 10)
	}
	out, err := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-i", "-p", strings.Join(list, ",")).Output()
	if err != nil && len(out) == 0 {
		// lsof exits 1 when there's nothing to list.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	return parseLsof(string(out)), nil
}

// parseLsof reads lsof's table: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME.
func parseLsof(s string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		pid, err := strconv.ParseUint(f[1], 10, 32)
		if err != nil {
			continue
		}
		proto := strings.ToLower(f[7])
		if f[4] == "IPv6" {
			proto += "6"
		}
		c := Conn{PID: uint32(pid), Proto: proto}
		name := strings.Join(f[8:], " ")
		if i := strings.Index(name, " ("); i >= 0 {
			c.State = strings.Trim(name[i+2:], ")")
			name = name[:i]
		}
		c.Local, c.Remote, _ = strings.Cut(name, "->")
		conns = append(conns, c)
	}
	return conns
}

// InjectedCode would look inside a running process for code that isn't from
// any file on disk. macOS enforces code signatures on what's mapped
// executable in hardened programs, and looking inside another process needs
// rights ABA doesn't ask for: not done on macOS.
func InjectedCode(pid uint32) (detail string, found bool) { return "", false }

// SideLoaded would look for a library nobody vouches for, loaded from the
// program's own folder. Not done on macOS yet.
func SideLoaded(pid uint32, image string, signed func(path string) bool) (lib string, found bool) {
	return "", false
}
