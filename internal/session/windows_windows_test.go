package session

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// The test itself has no window; Explorer, in a session someone is using,
// has the taskbar at least.
func TestVisibleWindows(t *testing.T) {
	if n, err := VisibleWindows([]uint32{uint32(os.Getpid())}); err != nil || n != 0 {
		t.Fatalf("a test without windows: %d, %v", n, err)
	}
	if n, err := VisibleWindows(nil); err != nil || n != 0 {
		t.Fatalf("nobody: %d, %v", n, err)
	}
	var sid uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid)
	if sid == 0 {
		t.Skip("no desktop in session 0")
	}
	shell := windows.GetShellWindow()
	if shell == 0 {
		t.Skip("no shell (Explorer) on this desktop")
	}
	var explorer uint32
	windows.GetWindowThreadProcessId(shell, &explorer)
	if n, err := VisibleWindows([]uint32{explorer}); err != nil || n == 0 {
		t.Fatalf("Explorer's windows: %d, %v", n, err)
	}
}
