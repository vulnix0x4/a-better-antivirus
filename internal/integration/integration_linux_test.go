// Package integration holds tests that need root and a real kernel: fanotify
// permission events, the cgroup freezer, the package database. They run in CI
// (GitHub's Linux runners have sudo) when ABA_INTEGRATION=1, as root, with
// ABA_TEST_USER naming an ordinary account to play the stealer.
package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/fanwatch"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// The test binary doubles as the harmless "stealer": started again with
// ABA_HELPER set, it opens a file or just keeps counting.
func TestMain(m *testing.M) {
	switch os.Getenv("ABA_HELPER") {
	case "open":
		ms, _ := strconv.Atoi(os.Getenv("ABA_DELAY_MS"))
		time.Sleep(time.Duration(ms) * time.Millisecond)
		out := "READ"
		if b, err := os.ReadFile(os.Getenv("ABA_PATH")); err != nil {
			out = "ERR " + err.Error()
		} else {
			out = fmt.Sprintf("READ %d", len(b))
		}
		os.WriteFile(os.Getenv("ABA_MARKER"), []byte(out), 0o666)
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "connect":
		// Try to reach ABA_ADDR every 100 ms; the marker says how the last try went.
		for i := 0; ; i++ {
			out := "OK"
			c, err := net.DialTimeout("tcp", os.Getenv("ABA_ADDR"), 300*time.Millisecond)
			if err != nil {
				out = "FAIL " + err.Error()
			} else {
				c.Close()
			}
			os.WriteFile(os.Getenv("ABA_MARKER"), []byte(fmt.Sprintf("%s %d", out, i)), 0o666)
			time.Sleep(100 * time.Millisecond)
		}
	case "tick":
		for i := 0; ; i++ {
			os.WriteFile(os.Getenv("ABA_MARKER"), []byte(strconv.Itoa(i)), 0o666)
			time.Sleep(10 * time.Millisecond)
		}
	}
	os.Exit(m.Run())
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("ABA_INTEGRATION") != "1" {
		t.Skip("set ABA_INTEGRATION=1 (as root) to run")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration tests need root")
	}
}

// player is the ordinary account the fake stealer runs as.
func player(t *testing.T) *syscall.Credential {
	t.Helper()
	name := os.Getenv("ABA_TEST_USER")
	if name == "" {
		t.Skip("set ABA_TEST_USER to an ordinary account")
	}
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}
}

// sandbox is a folder everyone can use (the stealer isn't root).
func sandbox(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aba-it-")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o777)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func bait(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(p, []byte("hunter2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0o644)
	return p
}

// helper starts the test binary in one of its helper modes, as cred.
func helper(t *testing.T, cred *syscall.Credential, mode, path, marker string, delay time.Duration) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = []string{"ABA_HELPER=" + mode, "ABA_PATH=" + path, "ABA_MARKER=" + marker, "ABA_DELAY_MS=" + strconv.Itoa(int(delay.Milliseconds()))}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	return cmd
}

func read(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func watcher(t *testing.T) *fanwatch.Watcher {
	t.Helper()
	w, err := fanwatch.New()
	if err != nil {
		t.Fatal(err)
	}
	if !w.Held() {
		t.Fatal("this kernel has no fanotify permission events; the runner's does")
	}
	t.Cleanup(w.Close)
	return w
}

// The kernel stops the opener inside its open, names it, and lets it go on
// only when ABA says so.
func TestOpenerIsHeldAndNamed(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	dir := sandbox(t)
	b, marker := bait(t, dir), filepath.Join(dir, "out")
	w := watcher(t)
	events, release := make(chan fanwatch.Event, 4), make(chan bool)
	w.OnOpen = func(ev fanwatch.Event) bool {
		events <- ev
		return <-release
	}
	w.Timeout = 20 * time.Second
	if err := w.Watch(b); err != nil {
		t.Fatal(err)
	}
	go w.Run()

	// ABA's own opens are never held (it repairs baits itself).
	if read(b) != "hunter2\n" {
		t.Fatal("the watcher's own process couldn't read the bait")
	}
	select {
	case ev := <-events:
		t.Fatalf("the watcher's own open was reported: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}

	cmd := helper(t, cred, "open", b, marker, 0)
	var ev fanwatch.Event
	select {
	case ev = <-events:
	case <-time.After(10 * time.Second):
		t.Fatal("the open wasn't reported")
	}
	if ev.PID != uint32(cmd.Process.Pid) || ev.Path != b || ev.Alias != "" || !ev.Held {
		t.Fatalf("event %+v, want pid %d opening %s, held", ev, cmd.Process.Pid, b)
	}
	if img, err := procinfo.ImagePath(ev.PID); err != nil || img != cmd.Path {
		t.Fatalf("ImagePath(%d) = %q, %v; it runs %s", ev.PID, img, err, cmd.Path)
	}
	if !procinfo.UserSession(ev.PID) || procinfo.Elevated(ev.PID) {
		t.Fatalf("pid %d should be an ordinary user's program", ev.PID)
	}
	time.Sleep(400 * time.Millisecond)
	if got := read(marker); got != "" {
		t.Fatalf("the opener got on while it was supposed to be held: %q", got)
	}
	release <- false
	if !waitFor(5*time.Second, func() bool { return strings.HasPrefix(read(marker), "READ 8") }) {
		t.Fatalf("after being let through the opener should have read the bait: %q", read(marker))
	}

	// And refused when ABA says no.
	marker2 := filepath.Join(dir, "out2")
	helper(t, cred, "open", b, marker2, 0)
	select {
	case <-events:
	case <-time.After(10 * time.Second):
		t.Fatal("the second open wasn't reported")
	}
	release <- true
	if !waitFor(5*time.Second, func() bool { return strings.HasPrefix(read(marker2), "ERR") }) {
		t.Fatalf("a refused open should fail: %q", read(marker2))
	}
}

// A hard link to a bait, or the bait under a new name, is the same file: the
// open is reported, with the name that was used. A new file put in the
// bait's place is watched once the baits are synced again.
func TestOtherNamesAndReplacement(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	dir := sandbox(t)
	b := bait(t, dir)
	w := watcher(t)
	events := make(chan fanwatch.Event, 8)
	w.OnOpen = func(ev fanwatch.Event) bool { events <- ev; return false }
	if errs := w.Sync([]string{b}); len(errs) > 0 {
		t.Fatal(errs)
	}
	go w.Run()
	if armed, want := w.Counts(); armed != 1 || want != 1 {
		t.Fatalf("Counts = %d of %d", armed, want)
	}
	open := func(path, name string) (fanwatch.Event, bool) {
		marker := filepath.Join(dir, "out-"+name)
		helper(t, cred, "open", path, marker, 0)
		select {
		case ev := <-events:
			return ev, true
		case <-time.After(1500 * time.Millisecond):
			if !strings.HasPrefix(read(marker), "READ") {
				t.Fatalf("%s: the helper didn't read %s: %q", name, path, read(marker))
			}
			return fanwatch.Event{}, false
		}
	}

	link := filepath.Join(dir, "notes.txt")
	if err := os.Link(b, link); err != nil {
		t.Fatal(err)
	}
	if ev, ok := open(link, "link"); !ok || ev.Path != b || ev.Alias != link {
		t.Fatalf("read through a hard link: reported=%v %+v, want bait %s under the name %s", ok, ev, b, link)
	}
	os.Remove(link)

	moved := filepath.Join(dir, "moved.txt")
	if err := os.Rename(b, moved); err != nil {
		t.Fatal(err)
	}
	if ev, ok := open(moved, "moved"); !ok || ev.Path != b || ev.Alias != moved {
		t.Fatalf("read after a rename: reported=%v %+v, want bait %s under the name %s", ok, ev, b, moved)
	}

	// Something else at the bait's path: a different file, not watched yet.
	if err := os.WriteFile(b, []byte("replaced\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w.Watched(b) {
		t.Fatal("a new file at the bait's path can't be watched before a sync")
	}
	if ev, ok := open(b, "replaced"); ok {
		t.Fatalf("an unwatched file was reported: %+v", ev)
	}
	if errs := w.Sync([]string{b}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if !w.Watched(b) {
		t.Fatal("after a sync the file at the bait's path is watched")
	}
	if ev, ok := open(b, "resynced"); !ok || ev.Path != b || ev.Alias != "" {
		t.Fatalf("read of the re-watched bait: reported=%v %+v", ok, ev)
	}
}

// Frozen means frozen: every thread stops, nothing running as the same user
// can thaw it, and a process frozen inside its open of a bait never gets to
// read it. Resume puts it back where it was.
func TestFreezer(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	if err := procinfo.FreezerStatus(); err != nil {
		t.Fatalf("no cgroup v2 freezer on the runner: %v", err)
	}
	dir := sandbox(t)
	counter := filepath.Join(dir, "count")
	cmd := helper(t, cred, "tick", "", counter, 0)
	pid := uint32(cmd.Process.Pid)
	if !waitFor(5*time.Second, func() bool { return read(counter) != "" }) {
		t.Fatal("the helper didn't start counting")
	}
	origin := readCgroup(pid)
	stopped := func() bool {
		a := read(counter)
		time.Sleep(300 * time.Millisecond)
		return a == read(counter)
	}

	if err := procinfo.Suspend(pid); err != nil {
		t.Fatal(err)
	}
	if !procinfo.Frozen(pid) || !waitFor(2*time.Second, stopped) {
		t.Fatalf("pid %d should be frozen (cgroup %s)", pid, readCgroup(pid))
	}
	ct, _ := procinfo.CreateTime(pid)
	if err := procinfo.Hold(pid, ct); err != nil {
		t.Fatalf("Hold: %v", err)
	}

	// What an accomplice running as the same user can try.
	asUser := func(name string, args ...string) (string, error) {
		c := exec.Command(name, args...)
		c.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		out, err := c.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	asUser("/bin/kill", "-CONT", strconv.Itoa(int(pid)))
	root := strings.TrimSuffix(cgroupPath(pid), readCgroup(pid))
	for _, target := range []string{filepath.Join(root, origin, "cgroup.procs"), filepath.Join(root, "cgroup.procs")} {
		if out, err := asUser("/bin/sh", "-c", fmt.Sprintf("echo %d > %s", pid, target)); err == nil {
			t.Errorf("a program of the same user moved the frozen process to %s: %s", target, out)
		}
	}
	if out, err := asUser("/bin/sh", "-c", "echo 0 > "+filepath.Join(cgroupPath(pid), "cgroup.freeze")); err == nil {
		t.Errorf("a program of the same user thawed the frozen group: %s", out)
	}
	if !procinfo.Frozen(pid) || !stopped() {
		t.Fatal("the frozen process got going again")
	}
	if esc := procinfo.Escaped(); len(esc) != 0 {
		t.Fatalf("nothing escaped, but Escaped() = %v", esc)
	}

	if err := procinfo.Resume(pid); err != nil {
		t.Fatal(err)
	}
	if !waitFor(3*time.Second, func() bool { return !stopped() }) {
		t.Fatal("after Resume the process should run again")
	}
	if got := readCgroup(pid); got != origin {
		t.Errorf("after Resume the process is in %s, it came from %s", got, origin)
	}
	procinfo.DropHolds(time.Now().Add(time.Hour), func(string) bool { return false })

	// Frozen again, then ended.
	if err := procinfo.Suspend(pid); err != nil {
		t.Fatal(err)
	}
	if err := procinfo.Kill(pid); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	if procinfo.Alive(pid, ct) {
		t.Fatal("Kill should end a frozen process")
	}
}

func readCgroup(pid uint32) string {
	for _, l := range strings.Split(read(fmt.Sprintf("/proc/%d/cgroup", pid)), "\n") {
		if strings.HasPrefix(l, "0::") {
			return l[3:]
		}
	}
	return ""
}

// cgroupPath is where pid's control group is in the file system.
func cgroupPath(pid uint32) string {
	for _, base := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		if _, err := os.Stat(filepath.Join(base, "cgroup.procs")); err == nil {
			return filepath.Join(base, readCgroup(pid))
		}
	}
	return "/sys/fs/cgroup" + readCgroup(pid)
}

// The order ABA relies on: freeze the opener while the kernel holds it, then
// allow the open. The process never runs again until it's resumed, so it
// never reads what it opened.
func TestFrozenInsideTheOpenNeverReads(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	dir := sandbox(t)
	b, marker := bait(t, dir), filepath.Join(dir, "out")
	w := watcher(t)
	frozen := make(chan uint32, 1)
	w.OnOpen = func(ev fanwatch.Event) bool {
		at := time.Now()
		if err := procinfo.Suspend(ev.PID); err != nil {
			t.Errorf("Suspend: %v", err)
		}
		t.Logf("frozen %v after the open was reported", time.Since(at))
		frozen <- ev.PID
		return false // the open goes ahead
	}
	if err := w.Watch(b); err != nil {
		t.Fatal(err)
	}
	go w.Run()
	helper(t, cred, "open", b, marker, 0)
	var pid uint32
	select {
	case pid = <-frozen:
	case <-time.After(10 * time.Second):
		t.Fatal("the open wasn't reported")
	}
	time.Sleep(700 * time.Millisecond)
	if got := read(marker); got != "" {
		t.Fatalf("a process frozen inside its open went on to read the bait: %q", got)
	}
	if !procinfo.Frozen(pid) {
		t.Fatal("it should still be frozen")
	}
	if err := procinfo.Resume(pid); err != nil {
		t.Fatal(err)
	}
	if !waitFor(5*time.Second, func() bool { return strings.HasPrefix(read(marker), "READ") }) {
		t.Fatalf("once resumed it should carry on: %q", read(marker))
	}
}

// The service manager runs as root and moves processes between control
// groups on request. This asks it, as the stealer's user, to take a frozen
// process into that user's own session: the one way out of the frozen group
// that doesn't need root. Whatever systemd answers, the process must end up
// frozen: either the request is refused, or Escaped notices and puts it back.
func TestFrozenProcessCannotBeMovedOutThroughSystemd(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	busctl, err := exec.LookPath("busctl")
	if err != nil {
		t.Skip("no busctl")
	}
	unit := fmt.Sprintf("user@%d.service", cred.Uid)
	if out, _ := exec.Command("systemctl", "is-active", unit).Output(); strings.TrimSpace(string(out)) != "active" {
		t.Skipf("%s isn't running (enable lingering for the test account to run this)", unit)
	}
	dir := sandbox(t)
	counter := filepath.Join(dir, "count")
	cmd := helper(t, cred, "tick", "", counter, 0)
	pid := uint32(cmd.Process.Pid)
	waitFor(5*time.Second, func() bool { return read(counter) != "" })
	if err := procinfo.Suspend(pid); err != nil {
		t.Fatal(err)
	}
	ct, _ := procinfo.CreateTime(pid)
	if err := procinfo.Hold(pid, ct); err != nil {
		t.Fatal(err)
	}
	defer func() {
		procinfo.DropHolds(time.Now().Add(time.Hour), func(string) bool { return false })
		procinfo.Kill(pid)
	}()

	// Into a group of the user's that exists (its manager's own), into the
	// unit itself, and into one that doesn't exist.
	for _, sub := range []string{"/init.scope", "", "/aba-escape"} {
		c := exec.Command(busctl, "--system", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
			"org.freedesktop.systemd1.Manager", "AttachProcessesToUnit", "ssau", unit, sub, "1", strconv.Itoa(int(pid)))
		c.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		out, err := c.CombinedOutput()
		t.Logf("asking systemd to move the frozen process into %s%s: err=%v out=%q", unit, sub, err, strings.TrimSpace(string(out)))
		time.Sleep(200 * time.Millisecond)
		if !procinfo.Frozen(pid) {
			break
		}
	}
	if procinfo.Frozen(pid) {
		t.Logf("systemd left it in the frozen group (cgroup %s)", readCgroup(pid))
		return
	}
	t.Logf("systemd moved it out, to %s: ABA has to notice", readCgroup(pid))
	esc := procinfo.Escaped()
	if len(esc) != 1 || esc[0] != pid {
		t.Fatalf("Escaped() = %v, want [%d]", esc, pid)
	}
	a := read(counter)
	time.Sleep(300 * time.Millisecond)
	if !procinfo.Frozen(pid) || a != read(counter) {
		t.Fatalf("the escaped process should be frozen again (cgroup %s)", readCgroup(pid))
	}
}

// Who vouches for what on this machine: the system's cat is a package's, in
// folders only root can write to; a copy of it in a user's folder is nobody's.
func TestProvenanceOnThisSystem(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("no cat")
	}
	r := provenance.Verify(cat)
	t.Logf("%s: %+v", cat, r)
	if !r.Valid || r.Signer == "" {
		t.Fatalf("the system's cat should be vouched for: %+v", r)
	}
	dir := sandbox(t)
	os.Chown(dir, int(cred.Uid), int(cred.Gid))
	mine := filepath.Join(dir, "cat")
	b, _ := os.ReadFile(cat)
	if err := os.WriteFile(mine, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if r := provenance.Verify(mine); r.Valid || r.Signed {
		t.Fatalf("a copy in a user's folder is nobody's: %+v", r)
	}
	// Root's own file in a folder a user can write to: still nobody's, since
	// the user can swap it.
	if ok, why := provenance.RootOnly(mine); ok {
		t.Fatalf("RootOnly(%s) should be false", mine)
	} else {
		t.Logf("not root-only: %s", why)
	}
}

// A library loaded into a genuine program from a user's folder is found.
func TestForeignCodeIsFound(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	libc := ""
	for _, c := range []string{"/usr/lib/x86_64-linux-gnu/libz.so.1", "/usr/lib/aarch64-linux-gnu/libz.so.1", "/usr/lib64/libz.so.1", "/usr/lib/libz.so.1"} {
		if _, err := os.Stat(c); err == nil {
			libc = c
			break
		}
	}
	sleep, err := exec.LookPath("sleep")
	if libc == "" || err != nil {
		t.Skip("no library to borrow")
	}
	dir := sandbox(t)
	lib := filepath.Join(dir, "libinnocent.so")
	b, _ := os.ReadFile(libc)
	if err := os.WriteFile(lib, b, 0o755); err != nil {
		t.Fatal(err)
	}
	clean := exec.Command(sleep, "30")
	clean.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	dirty := exec.Command(sleep, "30")
	dirty.Env = []string{"LD_PRELOAD=" + lib}
	dirty.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	for _, c := range []*exec.Cmd{clean, dirty} {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		defer func(c *exec.Cmd) { c.Process.Kill(); c.Wait() }(c)
	}
	time.Sleep(300 * time.Millisecond)
	if f, found := procinfo.ForeignCode(uint32(clean.Process.Pid)); found {
		t.Fatalf("a plain sleep has no foreign code, got %s", f)
	}
	if f, found := procinfo.ForeignCode(uint32(dirty.Process.Pid)); !found || f != lib {
		t.Fatalf("sleep with LD_PRELOAD=%s: found=%v %q", lib, found, f)
	}
	if d, found := procinfo.InjectedCode(uint32(dirty.Process.Pid)); !found {
		t.Fatal("InjectedCode should report it")
	} else {
		t.Log(d)
	}
}
