package integration

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// listener answers TCP connections on loopback until the test ends.
func listener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

// program copies the test binary into dir: a program of the user's own,
// which no package vouches for (cutting off the test binary itself would cut
// off this test).
func program(t *testing.T, dir, name string, cred *syscall.Credential) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	p := filepath.Join(dir, name)
	dst, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	dst.Close()
	os.Chown(p, int(cred.Uid), int(cred.Gid))
	return p
}

func connector(t *testing.T, exe string, cred *syscall.Credential, addr, marker string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(exe)
	cmd.Env = []string{"ABA_HELPER=connect", "ABA_ADDR=" + addr, "ABA_MARKER=" + marker}
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

// reaching waits until the connector's latest try went the way want says.
func reaching(t *testing.T, marker string, want bool, what string) {
	t.Helper()
	var got string
	ok := waitFor(8*time.Second, func() bool {
		got = read(marker)
		// Two tries in a row, so a try that was already under way doesn't count.
		return strings.HasPrefix(got, map[bool]string{true: "OK", false: "FAIL"}[want])
	})
	if ok {
		first := got
		time.Sleep(450 * time.Millisecond)
		got = read(marker)
		ok = strings.HasPrefix(got, map[bool]string{true: "OK", false: "FAIL"}[want]) && got != first
	}
	if !ok {
		t.Fatalf("%s: the program's last try to connect: %q", what, got)
	}
}

// Cutting a program off: its running process, and one that starts it
// afterwards, can't reach even a listener on loopback; let back, both can.
// The rules are in the kernel (they stay without the guard), and nothing is
// left once it's all removed.
func TestCutOffProgram(t *testing.T) {
	requireRoot(t)
	if err := netguard.Available(); err != nil {
		t.Fatalf("nftables should work on the runner: %v", err)
	}
	cred := player(t)
	dir := sandbox(t)
	addr := listener(t)
	exe := program(t, dir, "uploader", cred)
	t.Cleanup(func() { netguard.RemoveAll() })

	g := netguard.StartGuard(t.Logf)
	defer g.Close()

	m1 := filepath.Join(dir, "m1")
	first := connector(t, exe, cred, addr, m1)
	reaching(t, m1, true, "before anything is cut off")
	origin := procinfo.Cgroup(uint32(first.Process.Pid))

	if err := netguard.BlockProgram(exe); err != nil {
		t.Fatalf("BlockProgram: %v", err)
	}
	if !procinfo.CutOff(uint32(first.Process.Pid)) {
		t.Fatalf("the running program wasn't moved into the cut-off group: it's in %s", procinfo.Cgroup(uint32(first.Process.Pid)))
	}
	reaching(t, m1, false, "running when it was cut off")

	// Started afterwards: moved inside its execve().
	m2 := filepath.Join(dir, "m2")
	second := connector(t, exe, cred, addr, m2)
	if !waitFor(2*time.Second, func() bool { return procinfo.CutOff(uint32(second.Process.Pid)) }) {
		t.Fatalf("a program started after it was cut off isn't in the cut-off group: %s", procinfo.Cgroup(uint32(second.Process.Pid)))
	}
	if read(m2) != "" && strings.HasPrefix(read(m2), "OK") {
		t.Fatalf("a program started after it was cut off got through first: %q", read(m2))
	}
	reaching(t, m2, false, "started after it was cut off")

	// Its user can't take it out, or change the rules.
	try := exec.Command("/bin/sh", "-c", "echo "+strconv.Itoa(first.Process.Pid)+" > /sys/fs/cgroup/cgroup.procs")
	try.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	if try.Run() == nil && !procinfo.CutOff(uint32(first.Process.Pid)) {
		t.Fatal("its own user moved it out of the cut-off group")
	}

	st, err := netguard.GetStatus()
	if err != nil || st.Rules == 0 || st.Isolated {
		t.Fatalf("GetStatus = %+v, %v; want rules in place, not isolated", st, err)
	}

	// Without the guard (the service stopped or crashed), it stays cut off.
	g.Close()
	time.Sleep(300 * time.Millisecond)
	reaching(t, m1, false, "with the guard gone")

	if err := netguard.UnblockProgram(exe); err != nil {
		t.Fatalf("UnblockProgram: %v", err)
	}
	reaching(t, m1, true, "let back on the network")
	reaching(t, m2, true, "the one started later, let back")
	if got := procinfo.Cgroup(uint32(first.Process.Pid)); got != origin {
		t.Fatalf("let back, it should be where it came from (%s), not in %s", origin, got)
	}
	if st, err := netguard.GetStatus(); err != nil || st.Rules != 0 {
		t.Fatalf("after the last program is let back: %+v, %v; want no rules", st, err)
	}

	if err := netguard.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	for _, p := range []string{"/sys/fs/cgroup/file-access-monitor.blocked", "/var/lib/file-access-monitor/network.json"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("left behind: %s", p)
		}
	}
}

// A program the system vouches for is never cut off as a whole.
func TestSystemProgramNotCutOff(t *testing.T) {
	requireRoot(t)
	t.Cleanup(func() { netguard.RemoveAll() })
	err := netguard.BlockProgram("/usr/bin/cat")
	if err == nil || !strings.Contains(err.Error(), "the system's own") {
		t.Fatalf("BlockProgram(/usr/bin/cat) = %v, want a refusal that says why", err)
	}
	if st, _ := netguard.GetStatus(); st.Rules != 0 {
		t.Fatalf("rules were put in place anyway: %+v", st)
	}
}
