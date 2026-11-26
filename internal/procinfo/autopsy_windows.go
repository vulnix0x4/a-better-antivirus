package procinfo

// What the autopsy (package autopsy) and the flight recorder ask about a
// process on Windows.

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// StartedAt says when a process started.
func StartedAt(pid uint32) (time.Time, error) {
	ct, err := CreateTime(pid)
	if err != nil {
		return time.Time{}, err
	}
	ft := windows.Filetime{HighDateTime: uint32(uint64(ct) >> 32), LowDateTime: uint32(uint64(ct))}
	return time.Unix(0, ft.Nanoseconds()), nil
}

// ParentPID is the process that started pid (0 if unknown). Windows keeps
// the number only: the parent may have exited and its number been reused.
func ParentPID(pid uint32) uint32 {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var pbi windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), nil); err != nil {
		return 0
	}
	return uint32(pbi.InheritedFromUniqueProcessId)
}

const systemExtendedHandleInformation = 64

// handleEntry is SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.
type handleEntry struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

var procNtQuerySystemInformation = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation")

// handlesOf lists the handle values pid has open.
func handlesOf(pid uint32) ([]uintptr, error) {
	size := uint32(1 << 20)
	for try := 0; try < 8; try++ {
		buf := make([]byte, size)
		var ret uint32
		r, _, _ := procNtQuerySystemInformation.Call(systemExtendedHandleInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		const statusInfoLengthMismatch = 0xC0000004
		if uint32(r) == statusInfoLengthMismatch {
			size = ret + 1<<20
			if size < uint32(len(buf))*2 {
				size = uint32(len(buf)) * 2
			}
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: %#x", r)
		}
		n := *(*uintptr)(unsafe.Pointer(&buf[0]))
		head := 2 * unsafe.Sizeof(uintptr(0))
		esz := unsafe.Sizeof(handleEntry{})
		var out []uintptr
		for i := uintptr(0); i < n && head+(i+1)*esz <= uintptr(len(buf)); i++ {
			e := (*handleEntry)(unsafe.Pointer(&buf[head+i*esz]))
			if uint32(e.UniqueProcessID) == pid {
				out = append(out, e.HandleValue)
			}
		}
		return out, nil
	}
	return nil, errors.New("the handle list kept growing")
}

// OpenFiles lists the files on disk a process has open. Each name is asked
// for with a time limit: a frozen program in the middle of reading a file
// can keep the question waiting.
func OpenFiles(pid uint32) ([]string, error) {
	hs, err := handlesOf(pid)
	if err != nil {
		return nil, err
	}
	src, err := open(pid, windows.PROCESS_DUP_HANDLE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(src)
	self := windows.CurrentProcess()
	var out []string
	for _, hv := range hs {
		var dup windows.Handle
		if windows.DuplicateHandle(src, windows.Handle(hv), self, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
			continue
		}
		if t, _ := windows.GetFileType(dup); t != windows.FILE_TYPE_DISK {
			windows.CloseHandle(dup)
			continue
		}
		name, ok := finalPath(dup)
		if !ok {
			// Stuck: the handle stays with the question; give up on the rest.
			break
		}
		windows.CloseHandle(dup)
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// finalPath asks for the path of a file handle, giving up after a moment.
// ok is false if it gave up (the handle is then left to the question).
func finalPath(h windows.Handle) (string, bool) {
	done := make(chan string, 1)
	go func() {
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil || int(n) > len(buf) {
			done <- ""
			return
		}
		done <- strings.TrimPrefix(windows.UTF16ToString(buf[:n]), `\\?\`)
	}()
	select {
	case s := <-done:
		return s, true
	case <-time.After(500 * time.Millisecond):
		return "", false
	}
}

// ReadMemory hands fn a process's private memory (where its own data
// lives, not the files it mapped), a chunk at a time, at most limit bytes
// in all; fn returns false to stop.
func ReadMemory(pid uint32, limit int64, fn func(base uint64, b []byte) bool) (int64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	const (
		chunk    = 1 << 20
		memPriv  = 0x20000
		noAccess = windows.PAGE_NOACCESS | windows.PAGE_GUARD
	)
	buf := make([]byte, chunk)
	var total int64
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)) == nil; {
		next := mbi.BaseAddress + mbi.RegionSize
		if mbi.State == windows.MEM_COMMIT && mbi.Type == memPriv && mbi.Protect != 0 && mbi.Protect&noAccess == 0 {
			for off := uintptr(0); off < mbi.RegionSize; off += chunk {
				n := mbi.RegionSize - off
				if n > chunk {
					n = chunk
				}
				if total+int64(n) > limit {
					return total, nil
				}
				var got uintptr
				windows.ReadProcessMemory(h, mbi.BaseAddress+off, &buf[0], n, &got)
				if got == 0 {
					break
				}
				total += int64(got)
				if !fn(uint64(mbi.BaseAddress+off), buf[:got]) {
					return total, nil
				}
			}
		}
		if next <= addr {
			break
		}
		addr = next
	}
	return total, nil
}

var (
	procGetMappedFileNameW = windows.NewLazySystemDLL("psapi.dll").NewProc("GetMappedFileNameW")
	procQueryDosDeviceW    = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryDosDeviceW")
)

// CodeFiles lists the program files a process runs code from: its own
// program and every DLL it has loaded, wherever they are on disk. A
// self-unpacking program (a PyInstaller or Electron bundle) loads its
// libraries from the folder it unpacked itself into. The list comes from the
// files mapped into its memory, which works for a program of any
// architecture (an x64 program under emulation on Arm too).
func CodeFiles(pid uint32) ([]string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	const memImage = 0x1000000
	devices := dosDevices()
	seen := map[string]bool{}
	var out []string
	buf := make([]uint16, windows.MAX_LONG_PATH)
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)) == nil; {
		next := mbi.BaseAddress + mbi.RegionSize
		if mbi.Type == memImage && mbi.BaseAddress == mbi.AllocationBase {
			n, _, _ := procGetMappedFileNameW.Call(uintptr(h), mbi.BaseAddress, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if n > 0 && int(n) < len(buf) {
				if p := dosPath(windows.UTF16ToString(buf[:n]), devices); p != "" && !seen[strings.ToLower(p)] {
					seen[strings.ToLower(p)] = true
					out = append(out, p)
				}
			}
		}
		if next <= addr {
			break
		}
		addr = next
	}
	return out, nil
}

// dosDevices maps the kernel's names of the drives (\Device\HarddiskVolume3)
// to their letters (C:).
func dosDevices() map[string]string {
	m := map[string]string{}
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		d, _ := windows.UTF16PtrFromString(drive)
		n, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n > 0 {
			m[strings.ToLower(windows.UTF16ToString(buf[:n]))] = drive
		}
	}
	return m
}

// dosPath turns \Device\HarddiskVolume3\Users\x into C:\Users\x ("" if the
// drive isn't known).
func dosPath(p string, devices map[string]string) string {
	l := strings.ToLower(p)
	for dev, drive := range devices {
		if strings.HasPrefix(l, dev+`\`) {
			return drive + p[len(dev):]
		}
	}
	return ""
}
