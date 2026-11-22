package clipbait

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RunFakeClipper is the harmless clipper `aba clipboard test` catches: it
// does what a real one does (a hidden window Windows tells about every
// clipboard change; any wallet address on it is swapped) except that what it
// swaps in is a lookalike of its own, an invalid address. It gives up
// after d.
func RunFakeClipper(d time.Duration) {
	runtime.LockOSThread()
	mine := map[string]bool{}
	swaps := map[Coin]string{}
	for _, c := range Coins {
		swaps[c] = Lookalike(c)
		mine[swaps[c]] = true
	}
	h := makeWindow()
	if h == 0 {
		return
	}
	user32.NewProc("AddClipboardFormatListener").Call(h)
	getMessage := user32.NewProc("GetMessageW")
	time.AfterFunc(d, func() { windows.Exit(0) })
	var m struct {
		hwnd    uintptr
		message uint32
		wparam  uintptr
		lparam  uintptr
		time    uint32
		x, y    int32
		private uint32
	}
	for {
		if r, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0); int32(r) <= 0 {
			return
		}
		if m.message == 0x031D { // WM_CLIPBOARDUPDATE
			for i := 0; i < 20 && !fakeSwap(h, swaps, mine); i++ {
				time.Sleep(10 * time.Millisecond)
			}
		}
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// fakeSwap swaps an address on the clipboard; false: couldn't open it.
func fakeSwap(h uintptr, swaps map[Coin]string, mine map[string]bool) bool {
	if r, _, _ := pOpenClipboard.Call(h); r == 0 {
		return false
	}
	defer closeClip()
	t := readText()
	if t == "" || mine[t] {
		return true
	}
	for c, re := range patterns {
		if re.MatchString(t) {
			pEmptyClipboard.Call()
			u, _ := windows.UTF16FromString(swaps[c])
			setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2))
			return true
		}
	}
	return true
}
