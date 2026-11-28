package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

var procShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// requireAdmin returns nil if elevated. Otherwise it relaunches the same
// command through UAC, waits for it, and returns errRelaunched.
func requireAdmin() error {
	if winsec.IsElevated() {
		return nil
	}
	if yesMode {
		return errNeedsAdmin
	}
	fmt.Println()
	fmt.Println(" " + ui.Warn.Bold(true).Render("!") + " " + ui.Plain.Render("This needs administrator rights.") +
		ui.Dim.Render(" Approve the Windows prompt and it carries on in a new window."))
	if err := relaunchElevated(windows.SW_SHOWNORMAL, true); err != nil {
		return err
	}
	fmt.Println(" " + ui.Good.Render(ui.IconOK) + " " + ui.Plain.Render("Done") + ui.Dim.Render(" (in the administrator window)."))
	return errRelaunched
}

// requireAdminQuietly is requireAdmin for a command that only opens
// something (a report page): the administrator copy runs in a minimized
// window that closes by itself, and this one closes too once it's done.
// why says what the administrator rights are for.
func requireAdminQuietly(why string) error {
	if winsec.IsElevated() {
		return nil
	}
	if yesMode {
		return errNeedsAdmin
	}
	fmt.Println()
	fmt.Println(" " + ui.Plain.Render(why))
	fmt.Println(" " + ui.Dim.Render("Approve the Windows prompt. This window closes by itself."))
	if err := relaunchElevated(7 /* SW_SHOWMINNOACTIVE */, false); err != nil {
		return err
	}
	noPause = true
	return errRelaunched
}

// relaunchElevated runs this same command again through UAC and waits for
// it. pause: the new window waits for Enter at the end.
func relaunchElevated(show int32, pause bool) error {
	exe, _ := os.Executable()
	var args []string
	for _, a := range os.Args[1:] {
		if a != pauseFlag {
			args = append(args, syscall.EscapeArg(a))
		}
	}
	if pause {
		args = append(args, pauseFlag)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	cwd, _ := os.Getwd()
	dir, _ := windows.UTF16PtrFromString(cwd)
	sei := shellExecuteInfo{fMask: 0x40 /* SEE_MASK_NOCLOSEPROCESS */, lpVerb: verb, lpFile: file, lpParameters: params, lpDirectory: dir, nShow: show}
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	if r, _, e := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&sei))); r == 0 {
		if errors.Is(e, windows.ERROR_CANCELLED) {
			return errors.New("administrator permission was declined")
		}
		return fmt.Errorf("could not elevate: %v", e)
	}
	if sei.hProcess != 0 {
		windows.WaitForSingleObject(sei.hProcess, windows.INFINITE)
		var code uint32
		windows.GetExitCodeProcess(sei.hProcess, &code)
		windows.CloseHandle(sei.hProcess)
		if code != 0 {
			return fmt.Errorf("the administrator window reported an error (exit code %d)", code)
		}
	}
	return nil
}

// shouldPause: keep the window open when we were relaunched elevated or
// double-clicked from Explorer (the console would vanish instantly otherwise).
func shouldPause() bool {
	for _, a := range os.Args {
		if a == pauseFlag {
			return true
		}
	}
	snap, err := procinfo.Snapshot()
	if err != nil {
		return false
	}
	me, ok := snap[uint32(os.Getpid())]
	if !ok {
		return false
	}
	return strings.EqualFold(snap[me.PPID].Exe, "explorer.exe")
}
