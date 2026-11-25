package procinfo

import (
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// firstThread is pid's first thread, for the log of a failing test.
func firstThread(t *testing.T, pid uint32) SysThread {
	t.Helper()
	ps, err := SystemProcesses(func(p uint32) bool { return p == pid })
	if err != nil || len(ps) == 0 {
		t.Fatalf("pid %d not listed: %v", pid, err)
	}
	th, _ := ps[0].FirstThread()
	return th
}

// A process created suspended that never ran counts as "created suspended";
// once it runs it no longer does; and one suspended after it ran (the way
// ABA freezes a program) never does. Harmless: a console that would ping
// itself, started and ended by the test.
func TestCreatedSuspended(t *testing.T) {
	start := func(flags uint32) *exec.Cmd {
		t.Helper()
		cmd := exec.Command("cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { KillTree(uint32(cmd.Process.Pid)); cmd.Wait() })
		return cmd
	}

	sus := start(windows.CREATE_SUSPENDED)
	pid := uint32(sus.Process.Pid)
	if got, err := CreatedSuspended(pid); err != nil || !got {
		t.Fatalf("created suspended: %v, %v (first thread %+v)", got, err, firstThread(t, pid))
	}
	th := firstThread(t, pid)
	at, known := atThreadStart(th.TID)
	t.Logf("created suspended: first thread %+v, at its start: %v (known %v)", th, at, known)
	if err := Resume(pid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if got, _ := CreatedSuspended(pid); got {
		t.Fatalf("resumed, still counts as never ran (first thread %+v)", firstThread(t, pid))
	}

	ran := start(0)
	pid = uint32(ran.Process.Pid)
	time.Sleep(400 * time.Millisecond)
	if err := Suspend(pid); err != nil {
		t.Fatal(err)
	}
	defer Resume(pid)
	th = firstThread(t, pid)
	at, known = atThreadStart(th.TID)
	t.Logf("suspended after running: first thread %+v, at its start: %v (known %v)", th, at, known)
	if got, _ := CreatedSuspended(pid); got {
		t.Fatalf("a process suspended after it ran counts as created suspended (first thread %+v)", th)
	}
}

// What Browser finds out about a process: its starter (this test), how it
// was told to show its window, and its command line's switches.
func TestBrowserFacts(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul & rem --headless --remote-debugging-port=9222")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED, HideWindow: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { KillTree(uint32(cmd.Process.Pid)); cmd.Wait() }()
	pid := uint32(cmd.Process.Pid)
	img, _ := ImagePath(pid)
	b, err := Browser(pid, img)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := ImagePath(uint32(windows.GetCurrentProcessId()))
	if b.Main != pid || !b.CreatedSuspended || b.StarterGone || !samePath(b.StarterImage, self) || len(b.PIDs) != 1 {
		t.Fatalf("facts: %+v", b)
	}
	// HideWindow sets STARTF_USESHOWWINDOW with SW_HIDE.
	if len(b.Hidden) == 0 || !strings.Contains(b.Hidden[0], "hidden") {
		t.Fatalf("started hidden: %v", b.Hidden)
	}
	if len(b.Flags) != 2 {
		t.Fatalf("flags: %v", b.Flags)
	}
	if _, err := Browser(0xFFFFFFF0, ""); err != ErrGone {
		t.Fatalf("a process that doesn't exist: %v", err)
	}
}

func TestBrowserCommandLines(t *testing.T) {
	for cl, child := range map[string]bool{
		`"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --lang=en`:   true,
		`"C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc -childID 3`:              true,
		`"C:\Program Files\Google\Chrome\Application\chrome.exe"`:                             false,
		`"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default`: false,
	} {
		if BrowserChild(cl) != child {
			t.Errorf("BrowserChild(%s) = %v", cl, !child)
		}
	}
	if f := BrowserFlags(`chrome.exe --window-position=-32000,-32000 --no-startup-window`); len(f) != 2 {
		t.Errorf("flags: %v", f)
	}
	if f := BrowserFlags(`chrome.exe --window-position=100,80 --profile-directory="Profile 1"`); len(f) != 0 {
		t.Errorf("an ordinary window position: %v", f)
	}
}
