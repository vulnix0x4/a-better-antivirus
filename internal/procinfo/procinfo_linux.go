package procinfo

// Processes on Linux, read from /proc. Freezing is in freezer_linux.go.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// ---- /proc/<pid>/stat ----

// Stat is what ABA reads from a process's stat file.
type Stat struct {
	Comm      string // the kernel's short name for it
	State     byte   // R, S, Z (exited, not yet collected)…
	PPID      uint32
	TTY       int    // its controlling terminal (0: none)
	Flags     uint64 // PF_* flags
	StartTime uint64 // clock ticks after boot
}

const pfKThread = 0x00200000 // a kernel thread: no program behind it

// ReadStat reads /proc/<pid>/stat.
func ReadStat(pid uint32) (Stat, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Stat{}, err
	}
	return parseStat(string(b))
}

func parseStat(s string) (Stat, error) {
	// "pid (comm) state ppid …": comm may hold spaces and brackets itself, so
	// it ends at the last closing bracket.
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 0 || j < i || j+2 > len(s) {
		return Stat{}, errors.New("unreadable stat")
	}
	st := Stat{Comm: s[i+1 : j]}
	f := strings.Fields(s[j+1:])
	if len(f) < 20 {
		return Stat{}, errors.New("short stat")
	}
	st.State = f[0][0]
	num := func(k int) uint64 { v, _ := strconv.ParseUint(f[k], 10, 64); return v }
	st.PPID = uint32(num(1))
	tty, _ := strconv.Atoi(f[4])
	st.TTY = tty
	st.Flags = num(6)
	st.StartTime = num(19) // field 22 of the file
	return st, nil
}

var (
	bootOnce sync.Once
	bootSalt int64
)

// createTime makes a start time that is only ever compared: the ticks after
// boot at which the process started, under a number that differs from boot
// to boot (so a record kept across a restart never matches a new process
// that happens to get the same PID at the same tick).
func createTime(start uint64) int64 {
	bootOnce.Do(func() {
		b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
		h := fnv.New32a()
		h.Write(bytes.TrimSpace(b))
		bootSalt = int64(h.Sum32()&0xFFFFF) << 42
	})
	return bootSalt | int64(start&(1<<42-1))
}

// ---- looking at processes ----

// Snapshot lists all processes.
func Snapshot() (map[uint32]Entry, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := map[uint32]Entry{}
	for _, e := range ents {
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		st, err := ReadStat(uint32(n))
		if err != nil || st.State == 'Z' || st.State == 'X' {
			continue
		}
		out[uint32(n)] = Entry{PID: uint32(n), PPID: st.PPID, Exe: st.Comm, CreateTime: createTime(st.StartTime)}
	}
	return out, nil
}

// CreateTime says when a process started (see Entry.CreateTime). Together
// with the PID it identifies a process for good: PIDs get reused.
func CreateTime(pid uint32) (int64, error) {
	st, err := ReadStat(pid)
	if err != nil {
		return 0, err
	}
	if st.State == 'Z' || st.State == 'X' {
		return 0, errors.New("process has exited")
	}
	return createTime(st.StartTime), nil
}

// ImagePath returns the full path of the process executable: the file that
// is really running, wherever the process says it is.
//
// A process in a container or sandbox names its program by a path that means
// something else outside (its /usr/bin/python3 isn't this system's). So the
// path only counts if the file there is the very file that's running; if
// not, ABA looks for where that file is on this system (a flatpak's /app is a
// folder under /var/lib/flatpak), and failing that names it through the
// process's own view, /proc/<pid>/root/…, which no package ever vouches for.
func ImagePath(pid uint32) (string, error) {
	link := fmt.Sprintf("/proc/%d/exe", pid)
	p, err := os.Readlink(link)
	if err != nil {
		return "", err
	}
	// Deleted while running (a package upgrade does that to every running
	// program, and a stealer may do it to itself): the name it had.
	if strings.HasSuffix(p, " (deleted)") {
		return strings.TrimSuffix(p, " (deleted)"), nil
	}
	var running, named unix.Stat_t
	if unix.Stat(link, &running) != nil {
		return p, nil
	}
	if unix.Stat(p, &named) == nil && running.Dev == named.Dev && running.Ino == named.Ino {
		return p, nil
	}
	if hp := hostPath(pid, p, &running); hp != "" {
		return hp, nil
	}
	return fmt.Sprintf("/proc/%d/root%s", pid, p), nil
}

type mount struct{ dev, root, point string }

func mounts(pid string) []mount {
	f, err := os.Open("/proc/" + pid + "/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []mount
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		// 36 35 98:0 /root /mount/point options… - type source options
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			continue
		}
		out = append(out, mount{dev: f[2], root: unescape(f[3]), point: unescape(f[4])})
	}
	return out
}

// unescape undoes mountinfo's \040 for a space (and the like).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func under(p, dir string) (rest string, ok bool) {
	if dir == "/" {
		return p, true
	}
	if p == dir {
		return "", true
	}
	if strings.HasPrefix(p, dir+"/") {
		return p[len(dir):], true
	}
	return "", false
}

// hostPath finds the file a process in another mount namespace runs (p, in
// its own view) on this system: through the mount it's on. "" if it isn't
// reachable here, or isn't the same file.
func hostPath(pid uint32, p string, running *unix.Stat_t) string {
	var best mount
	found := false
	for _, m := range mounts(strconv.Itoa(int(pid))) {
		if _, ok := under(p, m.point); ok && (!found || len(m.point) >= len(best.point)) {
			best, found = m, true
		}
	}
	if !found {
		return ""
	}
	rest, _ := under(p, best.point)
	inFS := filepath.Join(best.root, rest) // the path inside that file system
	for _, m := range mounts("self") {
		if m.dev != best.dev {
			continue
		}
		rest, ok := under(inFS, m.root)
		if !ok {
			continue
		}
		cand := filepath.Join(m.point, rest)
		var st unix.Stat_t
		if unix.Stat(cand, &st) == nil && st.Dev == running.Dev && st.Ino == running.Ino {
			return cand
		}
	}
	return ""
}

// Args returns a process's arguments as it was started with them.
func Args(pid uint32) ([]string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil, nil
	}
	return strings.Split(string(b), "\x00"), nil
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
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
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
	var out []uint32
	for pid := range snap {
		if systemPID(pid) {
			continue
		}
		if img, err := ImagePath(pid); err == nil && img == path {
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
// init, and the kernel's own threads.
func systemPID(pid uint32) bool {
	if pid <= 2 {
		return true
	}
	st, err := ReadStat(pid)
	return err == nil && (st.PPID == 2 || st.Flags&pfKThread != 0)
}

// ---- who a process runs as ----

type cred struct {
	uid, euid, fsuid uint32
	gid              uint32
	capEff           uint64
}

func creds(pid uint32) (cred, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return cred{}, err
	}
	var c cred
	seen := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 5 && f[0] == "Uid:":
			u := func(k int) uint32 { v, _ := strconv.ParseUint(f[k], 10, 32); return uint32(v) }
			c.uid, c.euid, c.fsuid = u(1), u(2), u(4)
			seen++
		case len(f) >= 2 && f[0] == "Gid:":
			v, _ := strconv.ParseUint(f[1], 10, 32)
			c.gid = uint32(v)
		case len(f) >= 2 && f[0] == "CapEff:":
			c.capEff, _ = strconv.ParseUint(f[1], 16, 64)
		}
	}
	if seen == 0 {
		return c, errors.New("unreadable status")
	}
	return c, nil
}

// SelfElevated reports whether this process has administrator (root) rights.
func SelfElevated() bool { return os.Geteuid() == 0 }

// Elevated reports whether pid runs with root's rights: as root, or with
// capabilities that count on this system. When it can't tell it says yes: ABA
// is careful with those.
//
// "Root" inside a user namespace of its own making (unshare -r) doesn't
// count: that takes no rights at all, and a stealer would only have to do it
// to be treated as an administrator's tool.
func Elevated(pid uint32) bool {
	c, err := creds(pid)
	if err != nil {
		return true
	}
	if c.euid == 0 || c.fsuid == 0 {
		return true
	}
	return c.capEff != 0 && sameUserNS(pid)
}

func sameUserNS(pid uint32) bool {
	mine, err1 := os.Readlink("/proc/self/ns/user")
	theirs, err2 := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", pid))
	return err1 != nil || err2 != nil || mine == theirs
}

var (
	uidMinOnce sync.Once
	uidMin     uint32 = 1000
)

// person reports whether uid is an account people log in with, going by the
// line the system itself draws (UID_MIN in /etc/login.defs, 1000 by default).
func person(uid uint32) bool {
	uidMinOnce.Do(func() {
		b, err := os.ReadFile("/etc/login.defs")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "UID_MIN" {
				if v, err := strconv.ParseUint(f[1], 10, 32); err == nil && v > 0 {
					uidMin = uint32(v)
				}
			}
		}
	})
	return uid >= uidMin && uid != 65534 && uid != 65535
}

// UserSession reports whether pid is an ordinary user's program rather than
// a system service: it runs as an account people log in with.
func UserSession(pid uint32) bool {
	c, err := creds(pid)
	return err == nil && person(c.uid) && person(c.euid)
}

// UserID returns the account a process runs as, in the form ServiceAccount
// and config.UserInfo.SID use: its numeric user ID.
func UserID(pid uint32) (string, error) {
	c, err := creds(pid)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(c.uid), 10), nil
}

// ServiceAccount reports whether the account with this ID is one that system
// services run as (root included), not a person.
func ServiceAccount(id string) bool {
	v, err := strconv.ParseUint(id, 10, 32)
	return err != nil || !person(uint32(v))
}

// ---- what a process is attached to (for classify's rules) ----

// TTY returns the terminal a process is controlled from (0: none).
func TTY(pid uint32) int {
	st, err := ReadStat(pid)
	if err != nil {
		return 0
	}
	return st.TTY
}

// ParentPID returns the process that started pid (0 if unknown).
func ParentPID(pid uint32) uint32 {
	st, err := ReadStat(pid)
	if err != nil {
		return 0
	}
	return st.PPID
}

// Stdin says what a process reads its input from: a path such as /dev/pts/3,
// or "pipe:[…]", "socket:[…]".
func Stdin(pid uint32) string {
	p, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/0", pid))
	return p
}

// Cwd returns the folder a process is working in.
func Cwd(pid uint32) string {
	p, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	return strings.TrimSuffix(p, " (deleted)")
}

// ---- forensics ----

// ForeignCode looks at the program code a process has loaded and returns the
// first file among it that sits where a program running as you could have put
// it: a library slipped into an otherwise genuine program (LD_PRELOAD, a
// library path pointed at your folders, a plug-in).
//
// Code without a file behind it is left alone: language runtimes generate
// code as they go, and that looks the same.
func ForeignCode(pid uint32) (file string, found bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", false
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		// 7f1c…-7f1c… r-xp 00000000 08:02 1234  /usr/lib/x86_64-linux-gnu/libc.so.6
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) < 6 || !strings.Contains(f[1], "x") {
			continue
		}
		p := line[strings.Index(line, f[5]):]
		p = strings.TrimSuffix(p, " (deleted)")
		if !strings.HasPrefix(p, "/") || seen[p] {
			continue
		}
		seen[p] = true
		if strings.HasPrefix(p, "/memfd:") || strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/SYSV") ||
			strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/anon_hugepage") || strings.HasPrefix(p, "/[") {
			continue
		}
		if ok, _ := provenance.RootOnly(p); !ok {
			return p, true
		}
	}
	return "", false
}

// InjectedCode looks inside a running process for code nobody vouches for
// (see ForeignCode) and describes what it found.
func InjectedCode(pid uint32) (detail string, found bool) {
	// A process in a container sees its own files under the same names: its
	// libraries can't be judged by this system's folders.
	if img, err := ImagePath(pid); err != nil || strings.HasPrefix(img, "/proc/") {
		return "", false
	}
	if p, ok := ForeignCode(pid); ok {
		return "it's running code from " + p + ", a file anything running as you could have put there (a library loaded into it)", true
	}
	return "", false
}

// SideLoaded looks for a library that nobody vouches for, loaded by pid from
// its own program's folder. On Linux InjectedCode covers that, wherever the
// library is.
func SideLoaded(pid uint32, image string, signed func(path string) bool) (lib string, found bool) {
	return "", false
}
