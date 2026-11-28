package main

// Just enough COM to add the WebView2 event handlers that neither Wails nor
// go-webview2 registers: NavigationStarting, FrameNavigationStarting,
// NewWindowRequested and DownloadStarting. Indexes are positions in the
// interfaces' vtables, from WebView2.idl (the same order go-webview2's
// iCoreWebView2Vtbl has).

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

const (
	// ICoreWebView2
	idxAddNavigationStarting      = 7
	idxAddFrameNavigationStarting = 17
	idxAddNewWindowRequested      = 44
	// ICoreWebView2_4 (ICoreWebView2 + _2 + _3 + FrameCreated before it)
	idxAddDownloadStarting = 75

	// ICoreWebView2NavigationStartingEventArgs
	idxNavGetURI    = 3
	idxNavPutCancel = 8
	// ICoreWebView2NewWindowRequestedEventArgs
	idxNewWinGetURI     = 3
	idxNewWinPutHandled = 6
	// ICoreWebView2DownloadStartingEventArgs
	idxDlPutCancel  = 5
	idxDlPutHandled = 9
)

var iidICoreWebView2_4 = windows.GUID{Data1: 0x20d02d59, Data2: 0x6df2, Data3: 0x42dc, Data4: [8]byte{0xbd, 0x06, 0xf9, 0x8a, 0x69, 0x4b, 0x13, 0x02}}

// comCall calls method idx of the COM object obj.
func comCall(obj unsafe.Pointer, idx int, args ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Add(vtbl, uintptr(idx)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{uintptr(obj)}, args...)...)
	return r
}

func hresult(r uintptr) error {
	if int32(r) < 0 {
		return syscall.Errno(r)
	}
	return nil
}

// queryInterface asks obj for iid; the result must be released.
func queryInterface(obj unsafe.Pointer, iid *windows.GUID) (unsafe.Pointer, error) {
	var out unsafe.Pointer
	if err := hresult(comCall(obj, 0, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))); err != nil {
		return nil, err
	}
	return out, nil
}

func release(obj unsafe.Pointer) { comCall(obj, 2) }

// getString calls a get_X(LPWSTR*) method and frees the string.
func getString(obj unsafe.Pointer, idx int) string {
	var p *uint16
	if hresult(comCall(obj, idx, uintptr(unsafe.Pointer(&p)))) != nil || p == nil {
		return ""
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(p))
	return windows.UTF16PtrToString(p)
}

// eventHandler is a COM object for any ICoreWebView2*EventHandler: they all
// are IUnknown plus Invoke(sender, args). Handlers live as long as the
// process (handlers is never emptied), so COM's reference counts can be
// ignored.
type eventHandler struct {
	vtbl   *eventHandlerVtbl
	invoke func(sender, args unsafe.Pointer) uintptr
}

type eventHandlerVtbl struct {
	QueryInterface, AddRef, Release, Invoke uintptr
}

var (
	handlerVtbl = &eventHandlerVtbl{
		QueryInterface: windows.NewCallback(func(this *eventHandler, _ unsafe.Pointer, out *unsafe.Pointer) uintptr {
			*out = unsafe.Pointer(this)
			return 0
		}),
		AddRef:  windows.NewCallback(func(this *eventHandler) uintptr { return 1 }),
		Release: windows.NewCallback(func(this *eventHandler) uintptr { return 1 }),
		Invoke: windows.NewCallback(func(this *eventHandler, sender, args unsafe.Pointer) uintptr {
			return this.invoke(sender, args)
		}),
	}
	handlers []*eventHandler // keeps them alive
)

// addHandler registers invoke for the add_X event at idx of obj.
func addHandler(obj unsafe.Pointer, idx int, invoke func(sender, args unsafe.Pointer) uintptr) error {
	h := &eventHandler{vtbl: handlerVtbl, invoke: invoke}
	handlers = append(handlers, h)
	var token int64
	return hresult(comCall(obj, idx, uintptr(unsafe.Pointer(h)), uintptr(unsafe.Pointer(&token))))
}

// windowProc subclassing, to run code on the window's own (UI) thread,
// which WebView2 insists on.
var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procSetWindowLongPtr         = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProc           = user32.NewProc("CallWindowProcW")
	procPostMessage              = user32.NewProc("PostMessageW")
	procRegisterWinMsg           = user32.NewProc("RegisterWindowMessageW")
	procFindWindowEx             = user32.NewProc("FindWindowExW")
	procGetWindowThreadProcessID = user32.NewProc("GetWindowThreadProcessId")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procShowWindow               = user32.NewProc("ShowWindow")
	procMessageBox               = user32.NewProc("MessageBoxW")
)

const gwlpWndProc = ^uintptr(3) // GWLP_WNDPROC = -4

// findOwnWindow finds this process's top-level window of class.
func findOwnWindow(class string) uintptr {
	cls, _ := windows.UTF16PtrFromString(class)
	var hwnd uintptr
	for {
		hwnd, _, _ = procFindWindowEx.Call(0, hwnd, uintptr(unsafe.Pointer(cls)), 0)
		if hwnd == 0 {
			return 0
		}
		var pid uint32
		procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == windows.GetCurrentProcessId() {
			return hwnd
		}
	}
}

// findAppWindowInSession finds the window of the copy of the app already
// open in this session: a top-level window of class, of another process
// that is this same program (the installed app, or this very file) running
// elevated. Anyone may make a window of that class; this only brings the
// real one forward.
func findAppWindowInSession(class string) uintptr {
	cls, _ := windows.UTF16PtrFromString(class)
	var self uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &self)
	var hwnd uintptr
	for {
		hwnd, _, _ = procFindWindowEx.Call(0, hwnd, uintptr(unsafe.Pointer(cls)), 0)
		if hwnd == 0 {
			return 0
		}
		var pid, sess uint32
		procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != windows.GetCurrentProcessId() && windows.ProcessIdToSessionId(pid, &sess) == nil && sess == self && isElevatedApp(pid) {
			return hwnd
		}
	}
}

// isElevatedApp reports whether pid runs the installed app (or this same
// program file) with an elevated token.
func isElevatedApp(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return false
	}
	img := windows.UTF16ToString(buf[:n])
	self, _ := os.Executable()
	if !paths.Same(img, paths.InstalledApp()) && (self == "" || !paths.Same(img, self)) {
		return false
	}
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

// uiRunner runs functions on a window's thread, through a private window
// message handled by a subclass of its window procedure.
type uiRunner struct {
	hwnd, prev, msg uintptr
	jobs            chan func()
}

func newUIRunner(hwnd uintptr) (*uiRunner, error) {
	name, _ := windows.UTF16PtrFromString("ABA.app.run-on-ui-thread")
	msg, _, err := procRegisterWinMsg.Call(uintptr(unsafe.Pointer(name)))
	if msg == 0 {
		return nil, err
	}
	r := &uiRunner{hwnd: hwnd, msg: msg, jobs: make(chan func(), 16)}
	proc := windows.NewCallback(func(h, m, wp, lp uintptr) uintptr {
		if m == r.msg {
			for {
				select {
				case f := <-r.jobs:
					f()
				default:
					return 0
				}
			}
		}
		ret, _, _ := procCallWindowProc.Call(r.prev, h, m, wp, lp)
		return ret
	})
	prev, _, err := procSetWindowLongPtr.Call(hwnd, gwlpWndProc, proc)
	if prev == 0 {
		return nil, err
	}
	r.prev = prev
	return r, nil
}

// run runs f on the UI thread and waits for it.
func (r *uiRunner) run(f func()) {
	done := make(chan struct{})
	r.jobs <- func() { f(); close(done) }
	procPostMessage.Call(r.hwnd, r.msg, 0, 0)
	<-done
}

func messageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10 /* MB_ICONERROR */)
}

// confirmBox asks a Yes/No question in a native box owned by owner; No is
// the default button.
func confirmBox(owner uintptr, title, text string) bool {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	const mbYesNo, mbIconQuestion, mbDefButton2, idYes = 0x4, 0x20, 0x100, 6
	r, _, _ := procMessageBox.Call(owner, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbYesNo|mbIconQuestion|mbDefButton2)
	return r == idYes
}
