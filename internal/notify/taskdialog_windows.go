package notify

// The autopsy popup on Windows is a task dialog: a message box whose
// buttons can say what they do ("Show full report"), which MessageBox's
// Yes/No/Cancel can't.
//
// Task dialogs are in version 6 of Windows' common controls, which a
// program only gets when its manifest asks for it. aba.exe has no manifest,
// so the popup borrows Windows' own for the length of the dialog (an
// "activation context": the one Explorer uses, which asks for exactly
// that). Where that doesn't work, the popup is a message box with Yes = Show
// full report, No = Close.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procCreateActCtxW    = modKernel32.NewProc("CreateActCtxW")
	procActivateActCtx   = modKernel32.NewProc("ActivateActCtx")
	procDeactivateActCtx = modKernel32.NewProc("DeactivateActCtx")
	procReleaseActCtx    = modKernel32.NewProc("ReleaseActCtx")

	modUser32               = windows.NewLazySystemDLL("user32.dll")
	procSetWindowPos        = modUser32.NewProc("SetWindowPos")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
)

// actCtxW is ACTCTXW.
type actCtxW struct {
	cbSize                 uint32
	dwFlags                uint32
	lpSource               *uint16
	wProcessorArchitecture uint16
	wLangID                uint16
	lpAssemblyDirectory    *uint16
	lpResourceName         uintptr
	lpApplicationName      *uint16
	hModule                windows.Handle
}

const (
	actctxFlagAssemblyDirValid  = 0x4
	actctxFlagResourceNameValid = 0x8
)

// commonControls6 activates an activation context that asks for common
// controls 6, on this thread (keep it locked), and returns how to undo it.
func commonControls6() (undo func(), ok bool) {
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	sys := filepath.Join(win, "System32")
	tries := []actCtxW{
		// The manifest Explorer itself uses (asks for common controls 6).
		{lpSource: wstr(filepath.Join(win, "WindowsShell.Manifest"))},
		// The same, as shell32.dll carries it (resource 124).
		{dwFlags: actctxFlagResourceNameValid | actctxFlagAssemblyDirValid, lpSource: wstr(filepath.Join(sys, "shell32.dll")),
			lpAssemblyDirectory: wstr(sys), lpResourceName: 124},
	}
	for i := range tries {
		ac := &tries[i]
		ac.cbSize = uint32(unsafe.Sizeof(*ac))
		h, _, _ := procCreateActCtxW.Call(uintptr(unsafe.Pointer(ac)))
		if h == 0 || h == uintptr(windows.InvalidHandle) {
			continue
		}
		var cookie uintptr
		if r, _, _ := procActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie))); r == 0 {
			procReleaseActCtx.Call(h)
			continue
		}
		return func() {
			procDeactivateActCtx.Call(0, cookie)
			procReleaseActCtx.Call(h)
		}, true
	}
	return nil, false
}

func wstr(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// The task dialog's own values (commctrl.h).
const (
	tdfAllowDialogCancellation = 0x0008
	tdfUseCommandLinks         = 0x0010
	tdcbfCloseButton           = 0x0020
	tdErrorIcon                = 0xFFFE // MAKEINTRESOURCEW(-2)
	tdWarningIcon              = 0xFFFF // MAKEINTRESOURCEW(-1)
	tdnCreated                 = 0
	idShowReport               = 100

	// TASKDIALOGCONFIG and TASKDIALOG_BUTTON are packed to 1 byte
	// (pshpack1.h); these are their sizes and offsets on 64-bit Windows,
	// the only Windows ABA runs on.
	tdcSize          = 160
	tdcHwndParent    = 4
	tdcFlags         = 20
	tdcCommonButtons = 24
	tdcWindowTitle   = 28
	tdcMainIcon      = 36
	tdcMainInstr     = 44
	tdcContent       = 52
	tdcButtonCount   = 60
	tdcButtons       = 64
	tdcDefaultButton = 72
	tdcCallback      = 140
	tdbSize          = 12
)

var (
	taskDialogCallback     uintptr
	taskDialogCallbackOnce sync.Once
)

// onTop puts the dialog on top of everything and in front when it appears,
// like the message boxes (MB_TOPMOST | MB_SETFOREGROUND).
func onTop(hwnd, msg, wParam, lParam, data uintptr) uintptr {
	if msg == tdnCreated {
		const swpNoSize, swpNoMove = 0x1, 0x2
		procSetWindowPos.Call(hwnd, ^uintptr(0) /* HWND_TOPMOST */, 0, 0, 0, 0, swpNoSize|swpNoMove)
		procSetForegroundWindow.Call(hwnd)
	}
	return 0
}

// taskDialog shows a task dialog with one command-link button (label, with
// note as its second line) and Close. It returns whether the button was
// clicked, and false for ok when no task dialog could be shown.
func taskDialog(title, instruction, content, label, note string, icon uint32) (clicked, ok bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	undo, active := commonControls6()
	if !active {
		return false, false
	}
	defer undo()
	cc, err := windows.LoadLibrary("comctl32.dll")
	if err != nil {
		return false, false
	}
	proc, err := windows.GetProcAddress(cc, "TaskDialogIndirect")
	if err != nil {
		return false, false // common controls 5: no task dialogs
	}
	taskDialogCallbackOnce.Do(func() { taskDialogCallback = windows.NewCallback(onTop) })

	t, in, c, b := wstr(title), wstr(instruction), wstr(content), wstr(label+"\n"+note)
	var btn [tdbSize]byte
	binary.LittleEndian.PutUint32(btn[0:], idShowReport)
	binary.LittleEndian.PutUint64(btn[4:], uint64(uintptr(unsafe.Pointer(b))))

	var cfg [tdcSize]byte
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(cfg[off:], v) }
	put64 := func(off int, v uintptr) { binary.LittleEndian.PutUint64(cfg[off:], uint64(v)) }
	put32(0, tdcSize)
	put64(tdcHwndParent, 0)
	put32(tdcFlags, tdfAllowDialogCancellation|tdfUseCommandLinks)
	put32(tdcCommonButtons, tdcbfCloseButton)
	put64(tdcWindowTitle, uintptr(unsafe.Pointer(t)))
	mainIcon := uintptr(tdErrorIcon)
	if icon == mbIconWarning {
		mainIcon = tdWarningIcon
	}
	put64(tdcMainIcon, mainIcon)
	put64(tdcMainInstr, uintptr(unsafe.Pointer(in)))
	put64(tdcContent, uintptr(unsafe.Pointer(c)))
	put32(tdcButtonCount, 1)
	put64(tdcButtons, uintptr(unsafe.Pointer(&btn[0])))
	put32(tdcDefaultButton, idShowReport)
	put64(tdcCallback, taskDialogCallback)

	var pressed int32
	hr, _, _ := syscall.SyscallN(proc, uintptr(unsafe.Pointer(&cfg[0])), uintptr(unsafe.Pointer(&pressed)), 0, 0)
	// The strings and the button are referred to only from cfg's bytes,
	// which the collector doesn't look into: keep them until the dialog is gone.
	runtime.KeepAlive(t)
	runtime.KeepAlive(in)
	runtime.KeepAlive(c)
	runtime.KeepAlive(b)
	runtime.KeepAlive(&btn)
	if int32(hr) < 0 {
		return false, false
	}
	return pressed == idShowReport, true
}

// askReport shows the autopsy popup: the headline, the text, a "Show full
// report" button (the answer is true) and Close.
func askReport(title, headline, text string, icon uint32) bool {
	if clicked, ok := taskDialog(title, headline, text, showReportLabel, "Opens everything ABA found in your web browser", icon); ok {
		return clicked
	}
	return messageBox(title, headline+"\n\n"+text+"\n\nShow the full report now?\nYes = "+showReportLabel+" (in your web browser)\nNo = Close", mbYesNo|icon) == idYes
}
