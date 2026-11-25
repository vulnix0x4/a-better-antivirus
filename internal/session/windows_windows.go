package session

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32              = windows.NewLazySystemDLL("user32.dll")
	procIsWindowVisible = user32.NewProc("IsWindowVisible")
	procIsIconic        = user32.NewProc("IsIconic")
	procGetWindowRect   = user32.NewProc("GetWindowRect")
	procMonitorFromRect = user32.NewProc("MonitorFromRect")
)

type rect struct{ Left, Top, Right, Bottom int32 }

// VisibleWindows counts the top-level windows of the processes pids on this
// process's desktop that someone can see: shown, and either minimized to the
// taskbar or with some part on a screen. (Windows on another desktop, or
// placed far off every screen, don't count.) It must run in the person's
// session: see the hidden `aba window-check`, which the service runs there.
func VisibleWindows(pids []uint32) (int, error) {
	want := map[uint32]bool{}
	for _, p := range pids {
		want[p] = true
	}
	n := 0
	cb := syscall.NewCallback(func(hwnd windows.HWND, _ uintptr) uintptr {
		var pid uint32
		if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil || !want[pid] {
			return 1
		}
		if r, _, _ := procIsWindowVisible.Call(uintptr(hwnd)); r == 0 {
			return 1
		}
		if r, _, _ := procIsIconic.Call(uintptr(hwnd)); r != 0 {
			n++ // minimized: still a window you have open
			return 1
		}
		var rc rect
		if r, _, _ := procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc))); r == 0 {
			return 1
		}
		if rc.Right <= rc.Left || rc.Bottom <= rc.Top {
			return 1
		}
		const monitorDefaultToNull = 0
		if m, _, _ := procMonitorFromRect.Call(uintptr(unsafe.Pointer(&rc)), monitorDefaultToNull); m == 0 {
			return 1
		}
		n++
		return 1
	})
	if err := windows.EnumWindows(cb, nil); err != nil {
		return n, err
	}
	return n, nil
}
