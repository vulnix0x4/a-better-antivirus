package main

// What cookie stealers do to get past a browser's own encryption of its
// cookies, reduced to the part ABA can see, for ABA's own tests: start the
// genuine browser suspended, so it never runs as a browser and shows no
// window, put a little code into it, and have that code open a file in the
// browser's data from inside the browser.
//
// The code put into the browser opens the one file it's given, reads 16
// bytes of it into its own stack and closes it again: it takes nothing,
// keeps nothing and sends nothing (the file is one of ABA's baits, which
// are fake anyway). It's the observable behaviour only: the genuine
// browser's process opening a file, a moment after something else started
// it suspended.

import (
	"encoding/binary"
	"errors"
	"runtime"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	k32                    = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx     = k32.NewProc("VirtualAllocEx")
	procCreateRemoteThread = k32.NewProc("CreateRemoteThread")
	procCreateFileW        = k32.NewProc("CreateFileW")
	procReadFile           = k32.NewProc("ReadFile")
	procCloseHandle        = k32.NewProc("CloseHandle")
	procGetExitCodeThread  = k32.NewProc("GetExitCodeThread")
)

// startSuspended starts exe the way the stealers do: no command line of its
// own, created suspended, so it never runs (and never shows a window).
func startSuspended(exe string) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return pi, err
	}
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	err = windows.CreateProcess(app, nil, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &si, &pi)
	return pi, err
}

// openInside has the process h open file, read 16 bytes of it and close it
// again, from a thread of its own (see the top of this file). It waits up to
// wait for that thread, and says how many bytes it read (-1: it hadn't
// finished, e.g. because ABA froze the browser in the middle of its open).
func openInside(h windows.Handle, file string, wait time.Duration) (int, error) {
	if runtime.GOARCH != "amd64" {
		return 0, errors.New("only on x64")
	}
	for _, p := range []*windows.LazyProc{procCreateFileW, procReadFile, procCloseHandle, procVirtualAllocEx, procCreateRemoteThread} {
		if err := p.Find(); err != nil {
			return 0, err
		}
	}
	const pathAt = 0x200
	mem, _, err := procVirtualAllocEx.Call(uintptr(h), 0, 0x1000, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if mem == 0 {
		return 0, failed("VirtualAllocEx", err)
	}
	path := utf16.Encode([]rune(file + "\x00"))
	pb := make([]byte, 2*len(path))
	for i, c := range path {
		binary.LittleEndian.PutUint16(pb[2*i:], c)
	}
	if pathAt+len(pb) > 0x1000 {
		return 0, errors.New("path too long")
	}
	code := stub(uint64(mem+pathAt), uint64(procCreateFileW.Addr()), uint64(procReadFile.Addr()), uint64(procCloseHandle.Addr()))
	var n uintptr
	if err := windows.WriteProcessMemory(h, mem, &code[0], uintptr(len(code)), &n); err != nil {
		return 0, failed("WriteProcessMemory", err)
	}
	if err := windows.WriteProcessMemory(h, mem+pathAt, &pb[0], uintptr(len(pb)), &n); err != nil {
		return 0, failed("WriteProcessMemory", err)
	}
	th, _, err := procCreateRemoteThread.Call(uintptr(h), 0, 0, mem, 0, 0, 0)
	if th == 0 {
		return 0, failed("CreateRemoteThread", err)
	}
	defer windows.CloseHandle(windows.Handle(th))
	if ev, _ := windows.WaitForSingleObject(windows.Handle(th), uint32(wait.Milliseconds())); ev != windows.WAIT_OBJECT_0 {
		return -1, nil
	}
	var code32 uint32
	if r, _, _ := procGetExitCodeThread.Call(th, uintptr(unsafe.Pointer(&code32))); r == 0 {
		return -1, nil
	}
	return int(code32), nil
}

// stub is x64 code for a thread that does
//
//	h = CreateFileW(path, GENERIC_READ, FILE_SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
//	if h != INVALID_HANDLE_VALUE { ReadFile(h, 16 bytes on its stack, &n, NULL); CloseHandle(h) }
//	return n
//
// (Windows puts kernel32 at the same address in every process until the next
// restart, so the addresses here are the browser's too.)
func stub(path, createFile, readFile, closeHandle uint64) []byte {
	var c []byte
	emit := func(b ...byte) { c = append(c, b...) }
	imm64 := func(v uint64) { c = binary.LittleEndian.AppendUint64(c, v) }
	emit(0x48, 0x83, 0xEC, 0x68)                         // sub rsp, 0x68 (16-byte aligned for the calls)
	emit(0xC7, 0x44, 0x24, 0x50, 0x00, 0x00, 0x00, 0x00) // mov dword [rsp+0x50], 0 (bytes read)
	emit(0x48, 0xB9)                                     // mov rcx, path
	imm64(path)
	emit(0xBA, 0x00, 0x00, 0x00, 0x80)                         // mov edx, GENERIC_READ
	emit(0x41, 0xB8, 0x07, 0x00, 0x00, 0x00)                   // mov r8d, FILE_SHARE_READ|WRITE|DELETE
	emit(0x45, 0x31, 0xC9)                                     // xor r9d, r9d
	emit(0x48, 0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00) // mov qword [rsp+0x20], OPEN_EXISTING
	emit(0x48, 0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00) // mov qword [rsp+0x28], FILE_ATTRIBUTE_NORMAL
	emit(0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00) // mov qword [rsp+0x30], 0
	emit(0x48, 0xB8)                                           // mov rax, CreateFileW
	imm64(createFile)
	emit(0xFF, 0xD0)             // call rax
	emit(0x48, 0x83, 0xF8, 0xFF) // cmp rax, -1
	emit(0x74, 0x00)             // je done (patched below)
	je := len(c) - 1
	emit(0x48, 0x89, 0x44, 0x24, 0x58)                         // mov [rsp+0x58], rax
	emit(0x48, 0x89, 0xC1)                                     // mov rcx, rax
	emit(0x48, 0x8D, 0x54, 0x24, 0x38)                         // lea rdx, [rsp+0x38] (16 bytes)
	emit(0x41, 0xB8, 0x10, 0x00, 0x00, 0x00)                   // mov r8d, 16
	emit(0x4C, 0x8D, 0x4C, 0x24, 0x50)                         // lea r9, [rsp+0x50]
	emit(0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00) // mov qword [rsp+0x20], 0
	emit(0x48, 0xB8)                                           // mov rax, ReadFile
	imm64(readFile)
	emit(0xFF, 0xD0)                   // call rax
	emit(0x48, 0x8B, 0x4C, 0x24, 0x58) // mov rcx, [rsp+0x58]
	emit(0x48, 0xB8)                   // mov rax, CloseHandle
	imm64(closeHandle)
	emit(0xFF, 0xD0) // call rax
	c[je] = byte(len(c) - (je + 1))
	emit(0x8B, 0x44, 0x24, 0x50) // done: mov eax, dword [rsp+0x50] (the thread's exit code: bytes read)
	emit(0x48, 0x83, 0xC4, 0x68) // add rsp, 0x68
	emit(0xC3)                   // ret
	return c
}
