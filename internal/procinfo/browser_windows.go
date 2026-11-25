package procinfo

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Browser looks at the browser instance the process pid (running image)
// belongs to: it finds the main process (walking up from a browser's own
// child process, by its command line), lists the instance, and gathers how
// the main process was started. Call it before suspending anything: a
// suspension ABA makes doesn't look like "created suspended" (see NeverRan),
// but the earlier the facts, the truer.
func Browser(pid uint32, image string) (*BrowserInstance, error) {
	snap, err := Snapshot()
	if err != nil {
		return nil, err
	}
	cur, ok := snap[pid]
	if !ok {
		return nil, ErrGone
	}
	if image == "" {
		if image, err = ImagePath(pid); err != nil {
			return nil, ErrGone
		}
	}
	// The main process: up through the browser's own child processes. Only
	// the same executable counts (not just the same name: a stealer can call
	// itself chrome.exe).
	main := cur
	cmd, _ := CommandLine(main.PID)
	for i := 0; i < 8 && BrowserChild(cmd); i++ {
		pp, ok := parentOf(snap, main)
		if !ok {
			break
		}
		img, err := ImagePath(pp.PID)
		if err != nil || !samePath(img, image) {
			break
		}
		main = pp
		cmd, _ = CommandLine(main.PID)
	}
	b := &BrowserInstance{Main: main.PID, MainCreate: main.CreateTime, Image: image, CommandLine: cmd,
		PIDs: Tree(snap, main.PID), Flags: BrowserFlags(cmd)}

	// What started it: the first ancestor that isn't this browser (one that
	// restarted itself to update is the same browser).
	b.StarterGone = true
	for p, i := main, 0; i < 8; i++ {
		pp, ok := parentOf(snap, p)
		if !ok {
			break
		}
		img, err := ImagePath(pp.PID)
		if err == nil && samePath(img, image) {
			p = pp
			continue
		}
		b.Starter, b.StarterImage, b.StarterCreate, b.StarterGone = pp.PID, img, pp.CreateTime, false
		if img == "" {
			b.StarterImage = pp.Exe
		}
		break
	}

	b.CreatedSuspended, _ = CreatedSuspended(main.PID)
	b.Hidden = startedHidden(main.PID)
	return b, nil
}

// parentOf is p's parent, if it's still running and isn't a later process
// that reused the parent's PID.
func parentOf(snap map[uint32]Entry, p Entry) (Entry, bool) {
	pp, ok := snap[p.PPID]
	if !ok || p.PPID == 0 || p.PPID == p.PID || systemPID(p.PPID) {
		return Entry{}, false
	}
	if pp.CreateTime != 0 && p.CreateTime != 0 && pp.CreateTime > p.CreateTime {
		return Entry{}, false // created after its "child": a reused PID
	}
	return pp, true
}

// What a process was told about its window when it was started, kept in its
// RTL_USER_PROCESS_PARAMETERS (x64 / arm64 layout): the STARTUPINFO flags
// and show command, and the desktop it was put on.
const (
	pebProcessParameters = 0x20
	uppFlags             = 0x08
	uppWindowFlags       = 0xA4
	uppShowWindow        = 0xA8
	uppDesktopInfo       = 0xC0
	uppSize              = 0xD0
	uppNormalized        = 0x1 // RTL_USER_PROC_PARAMS_NORMALIZED: string buffers are addresses, not offsets

	startfUseShowWindow = 0x1
	swHide              = 0
)

// StartupWindow is how a process was told to show itself when it was started.
type StartupWindow struct {
	UseShowWindow bool   // STARTF_USESHOWWINDOW was set
	ShowWindow    uint16 // the SW_ command, when it was
	Desktop       string // station\desktop it was started on ("" = its parent's)
}

// StartupWindowOf reads how pid was told to show itself (see StartupWindow).
func StartupWindowOf(pid uint32) (StartupWindow, error) {
	var sw StartupWindow
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ)
	if err != nil {
		return sw, err
	}
	defer windows.CloseHandle(h)
	var pbi windows.PROCESS_BASIC_INFORMATION
	var n uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &n); err != nil {
		return sw, err
	}
	var params uintptr
	if err := readMem(h, uintptr(unsafe.Pointer(pbi.PebBaseAddress))+pebProcessParameters, unsafe.Pointer(&params), unsafe.Sizeof(params)); err != nil {
		return sw, err
	}
	if params == 0 {
		return sw, windows.ERROR_INVALID_DATA
	}
	buf := make([]byte, uppSize)
	if err := readMem(h, params, unsafe.Pointer(&buf[0]), uintptr(len(buf))); err != nil {
		return sw, err
	}
	sw.UseShowWindow = le32(buf, uppWindowFlags)&startfUseShowWindow != 0
	sw.ShowWindow = uint16(le32(buf, uppShowWindow))
	length := int(*(*uint16)(unsafe.Pointer(&buf[uppDesktopInfo])))
	ptr := uintptr(le64(buf, uppDesktopInfo+8))
	if length > 0 && length <= 512 && ptr != 0 {
		if le32(buf, uppFlags)&uppNormalized == 0 {
			ptr += params
		}
		s := make([]uint16, length/2)
		if readMem(h, ptr, unsafe.Pointer(&s[0]), uintptr(length)) == nil {
			sw.Desktop = windows.UTF16ToString(s)
		}
	}
	return sw, nil
}

func readMem(h windows.Handle, addr uintptr, to unsafe.Pointer, size uintptr) error {
	var got uintptr
	if err := windows.ReadProcessMemory(h, addr, (*byte)(to), size, &got); err != nil {
		return err
	}
	if got != size {
		return windows.ERROR_PARTIAL_COPY
	}
	return nil
}

// HiddenStart says, in plain words, how sw starts a program without showing
// it: told to hide its window, or put on a desktop other than the one you
// see. Empty when it doesn't.
func HiddenStart(sw StartupWindow) []string {
	var out []string
	if sw.UseShowWindow && sw.ShowWindow == swHide {
		out = append(out, "it was told to keep its window hidden")
	}
	if d := strings.TrimSpace(sw.Desktop); d != "" && !strings.EqualFold(d, `winsta0\default`) {
		out = append(out, "it was put on a desktop you can't see ("+d+")")
	}
	return out
}

func startedHidden(pid uint32) []string {
	sw, err := StartupWindowOf(pid)
	if err != nil {
		return nil
	}
	return HiddenStart(sw)
}
