package procinfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// busyChild starts a process that keeps appending to a file, and returns it
// with a func that reports whether it's making progress (i.e. running).
func busyChild(t *testing.T) (*exec.Cmd, func() bool) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.txt")
	c := exec.Command("cmd.exe", "/c", "for /L %i in (1,1,5000000) do @echo %i>>"+out)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	size := func() int64 {
		fi, err := os.Stat(out)
		if err != nil {
			return 0
		}
		return fi.Size()
	}
	running := func() bool {
		a := size()
		time.Sleep(400 * time.Millisecond)
		return size() != a
	}
	for i := 0; i < 20 && !running(); i++ {
	}
	return c, running
}

// The whole point of a hold: another program running as the same user can
// undo a plain suspension with one call, but not a hold.
func TestHoldSurvivesAnAccomplice(t *testing.T) {
	c, running := busyChild(t)
	pid := uint32(c.Process.Pid)
	ct, _ := CreateTime(pid)

	if err := Suspend(pid); err != nil {
		t.Fatal(err)
	}
	if running() {
		t.Fatal("still running after Suspend")
	}
	Resume(pid) // what an accomplice does
	if !running() {
		t.Fatal("expected a plain suspension to be undone by a resume (the weakness a hold fixes)")
	}

	Suspend(pid)
	if err := Hold(pid, ct); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	for i := 0; i < 5; i++ {
		Resume(pid) // the accomplice again, repeatedly
	}
	if running() {
		t.Fatal("a held process was un-frozen by a plain resume")
	}
	if Held() != 1 {
		t.Fatalf("Held = %d", Held())
	}
	Unhold(pid, ct)
	if !Alive(pid, ct) {
		t.Fatal("releasing a hold killed the process")
	}
	if !running() {
		t.Fatal("still frozen after the hold was released")
	}
}

// If whoever holds it goes away without releasing (the service crashed), the
// held process dies rather than staying frozen with nobody able to thaw it.
func TestAbandonedHoldKills(t *testing.T) {
	c, _ := busyChild(t)
	pid := uint32(c.Process.Pid)
	ct, _ := CreateTime(pid)
	Suspend(pid)
	if err := Hold(pid, ct); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	holdMu.Lock()
	job := holds[HoldName(pid, ct)]
	delete(holds, HoldName(pid, ct))
	holdMu.Unlock()
	windows.CloseHandle(job) // what a crash does
	for i := 0; i < 20 && Alive(pid, ct); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if Alive(pid, ct) {
		t.Fatal("an abandoned hold left its process alive")
	}
}

// `aba resume` takes a process off the record and resumes it; the service
// then lets go of the hold. Whichever happens first, the process ends up
// running, and letting go never kills it.
func TestServiceDropsHoldsThatAreOffTheRecord(t *testing.T) {
	c, running := busyChild(t)
	pid := uint32(c.Process.Pid)
	ct, _ := CreateTime(pid)
	Suspend(pid)
	if err := Hold(pid, ct); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	made := time.Now()
	Resume(pid) // the CLI's part; the hold is still on
	if running() {
		t.Fatal("running while still held")
	}
	// A snapshot of the record taken before the hold was made says nothing about it.
	DropHolds(made.Add(-time.Minute), func(string) bool { return false })
	if Held() != 1 || running() {
		t.Fatal("a hold newer than the snapshot was dropped")
	}
	// Still on record: kept.
	DropHolds(time.Now(), func(name string) bool { return name == HoldName(pid, ct) })
	if Held() != 1 {
		t.Fatal("a hold that's still on record was dropped")
	}
	// Off the record: released.
	DropHolds(time.Now(), func(string) bool { return false })
	if Held() != 0 {
		t.Fatalf("Held = %d", Held())
	}
	time.Sleep(300 * time.Millisecond)
	if !Alive(pid, ct) || !running() {
		t.Fatal("dropping the hold killed the process or left it frozen")
	}
	Unhold(pid+1_000_000, 1) // a hold that doesn't exist: nothing happens
}

func TestAncestorsAndUser(t *testing.T) {
	pid := uint32(os.Getpid())
	if a := Ancestors(pid, 4); len(a) == 0 || a[0].PID == pid {
		t.Fatalf("Ancestors = %+v", a)
	}
	sid, err := UserID(pid)
	if err != nil || len(sid) < 8 || sid[:4] != "S-1-" {
		t.Fatalf("UserSID = %q, %v", sid, err)
	}
	exe, _ := os.Executable()
	found := false
	for _, p := range RunningImage(exe) {
		found = found || p == pid
	}
	if !found {
		t.Fatal("RunningImage didn't find this test binary")
	}
}
