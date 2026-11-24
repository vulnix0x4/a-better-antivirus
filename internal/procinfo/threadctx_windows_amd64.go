package procinfo

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// x64 CONTEXT: where its flags and instruction pointer are, and its size.
const (
	ctxSize         = 0x4D0
	ctxFlagsOffset  = 0x30
	ctxPCOffset     = 0xF8
	ctxControlFlags = 0x100001 // CONTEXT_AMD64 | CONTEXT_CONTROL
)

var (
	procGetThreadContext   = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetThreadContext")
	procRtlUserThreadStart = ntdll.NewProc("RtlUserThreadStart")
)

// atThreadStart reports whether the suspended thread tid is still where every
// thread begins (ntdll's RtlUserThreadStart, with the context Windows gave it
// when it was created): it has never run. known is false when that can't be
// read (no access).
func atThreadStart(tid uint32) (at, known bool) {
	if procRtlUserThreadStart.Find() != nil {
		return false, false
	}
	start := procRtlUserThreadStart.Addr()
	h, err := windows.OpenThread(windows.THREAD_GET_CONTEXT|windows.THREAD_QUERY_LIMITED_INFORMATION, false, tid)
	if err != nil {
		return false, false
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, ctxSize+16)
	off := (16 - int(uintptr(unsafe.Pointer(&buf[0]))&15)) & 15 // CONTEXT must be 16-byte aligned
	ctx := buf[off : off+ctxSize]
	*(*uint32)(unsafe.Pointer(&ctx[ctxFlagsOffset])) = ctxControlFlags
	if r, _, _ := procGetThreadContext.Call(uintptr(h), uintptr(unsafe.Pointer(&ctx[0]))); r == 0 {
		return false, false
	}
	return uintptr(le64(ctx, ctxPCOffset)) == start, true
}
