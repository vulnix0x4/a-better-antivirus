package clipbait

import (
	"bytes"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// holds reports whether process pid has any of needles in its own memory, as
// UTF-16 (how the clipboard hands text over) or UTF-8. Every program that read
// the bait off the clipboard got a copy of it, and a clipper also has the
// address it swapped in; that narrows down who to pause.
//
// Only private memory is read (where a program's own data lives, not the
// files it has mapped), and at most maxScan bytes of it.
func holds(pid uint32, needles ...string) bool {
	h, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var pats [][]byte
	longest := 0
	for _, n := range needles {
		if n == "" {
			continue
		}
		u16 := make([]byte, 0, len(n)*2)
		for _, c := range utf16.Encode([]rune(n)) {
			u16 = append(u16, byte(c), byte(c>>8))
		}
		pats = append(pats, []byte(n), u16)
		if len(u16) > longest {
			longest = len(u16)
		}
	}
	if len(pats) == 0 {
		return false
	}
	const (
		chunk    = 1 << 20
		maxScan  = 1 << 30
		memPriv  = 0x20000
		noAccess = windows.PAGE_NOACCESS | windows.PAGE_GUARD
	)
	buf := make([]byte, chunk+longest)
	scanned := 0
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)) == nil; {
		next := mbi.BaseAddress + mbi.RegionSize
		if mbi.State == windows.MEM_COMMIT && mbi.Type == memPriv && mbi.Protect != 0 && mbi.Protect&noAccess == 0 {
			// Overlap the chunks so a match across a boundary isn't missed.
			for off := uintptr(0); off < mbi.RegionSize; off += chunk {
				n := mbi.RegionSize - off
				if n > uintptr(len(buf)) {
					n = uintptr(len(buf))
				}
				var got uintptr
				windows.ReadProcessMemory(h, mbi.BaseAddress+off, &buf[0], n, &got)
				for _, p := range pats {
					if bytes.Contains(buf[:got], p) {
						return true
					}
				}
				if scanned += int(got); scanned > maxScan {
					return false
				}
			}
		}
		if next <= addr {
			break
		}
		addr = next
	}
	return false
}
