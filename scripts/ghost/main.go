// Command ghost reads one file in a way that used to get past ABA, then
// waits around (so the end-to-end test can see it frozen).
//
// CI-only helper, like scripts/medium: the e2e test points it at a bait to
// check that each of these is caught. Not part of ABA.
//
//	ghost plain    <file>   an ordinary read, for comparison
//	ghost ghost    <file>   open without letting Windows pause the open, then read
//	ghost map      <file>   the same, never asking for read access: open for
//	                        execute, map the file into memory, read that
//	ghost link     <file>   read it through a hard link (a second name for the file)
//	ghost linkgone <file>   the same, deleting the link again right after
//	ghost resume   <pid>    what an accomplice does: un-suspend a frozen process
//
// With a third argument, a file, the reader appends a line to it ten times a
// second after its read: a heartbeat that shows whether it's running or frozen.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileReadData         = 0x1
	fileExecute          = 0x20
	completeIfOplocked   = 0x100 // FILE_COMPLETE_IF_OPLOCKED
	nonDirectory, syncIO = 0x40, 0x20
)

func ntOpen(path string, access, options uint32) (windows.Handle, error) {
	us, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: us, Attributes: 0x40}
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &iosb, nil, 0, 7, 1, options|nonDirectory|syncIO, 0, 0)
	if h == 0 {
		return 0, err
	}
	return h, nil
}

func read(h windows.Handle) int {
	buf := make([]byte, 512)
	var n uint32
	windows.ReadFile(h, buf, &n, nil)
	return int(n)
}

func mapped(h windows.Handle) int {
	nt := windows.NewLazySystemDLL("ntdll.dll")
	var sec windows.Handle
	if r, _, _ := nt.NewProc("NtCreateSection").Call(uintptr(unsafe.Pointer(&sec)), 0x8|0x1, 0, 0, windows.PAGE_EXECUTE, 0x8000000, uintptr(h)); r != 0 {
		return 0
	}
	var base unsafe.Pointer
	var size uintptr
	if r, _, _ := nt.NewProc("NtMapViewOfSection").Call(uintptr(sec), ^uintptr(0), uintptr(unsafe.Pointer(&base)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 2, 0, windows.PAGE_EXECUTE); r != 0 {
		return 0
	}
	return len(append([]byte(nil), unsafe.Slice((*byte)(base), 8)...)) // copy 8 bytes out of the mapping
}

// resume un-suspends pid the way any program running as the same user can.
func resume(pid uint32) error {
	h, err := windows.OpenProcess(0x0800 /* PROCESS_SUSPEND_RESUME */, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	nt := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")
	for i := 0; i < 5; i++ {
		if r, _, _ := nt.Call(uintptr(h)); r != 0 {
			return fmt.Errorf("NtResumeProcess: 0x%08x", uint32(r))
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: ghost plain|ghost|map|link|linkgone <file> [heartbeat file]  |  ghost resume <pid>")
		os.Exit(2)
	}
	mode, path := os.Args[1], os.Args[2]
	if mode == "resume" {
		var pid uint32
		fmt.Sscan(path, &pid)
		if err := resume(pid); err != nil {
			fmt.Fprintln(os.Stderr, "ghost:", err)
			os.Exit(1)
		}
		fmt.Println("resumed")
		return
	}
	note := func(format string, a ...any) { // progress, next to the heartbeat file
		if len(os.Args) == 4 {
			if f, err := os.OpenFile(os.Args[3]+".status", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				fmt.Fprintf(f, format+"\n", a...)
				f.Close()
			}
		}
	}
	note("started as pid %d", os.Getpid())
	time.Sleep(700 * time.Millisecond) // like `aba test-reader`: let the test note our PID first
	var h windows.Handle
	var err error
	got := 0
	switch mode {
	case "plain":
		if h, err = ntOpen(path, fileReadData, 0); err == nil {
			got = read(h)
		}
	case "ghost":
		if h, err = ntOpen(path, fileReadData, completeIfOplocked); err == nil {
			got = read(h)
		}
	case "map":
		if h, err = ntOpen(path, fileExecute, completeIfOplocked); err == nil {
			got = mapped(h)
		}
	case "link", "linkgone":
		link := filepath.Join(os.TempDir(), fmt.Sprintf("cache-%d.dat", os.Getpid()))
		os.Remove(link)
		if err = os.Link(path, link); err == nil {
			if h, err = ntOpen(link, fileReadData, 0); err == nil {
				got = read(h)
				windows.CloseHandle(h)
			}
			if mode == "linkgone" {
				os.Remove(link)
			}
		}
	default:
		os.Exit(2)
	}
	if err != nil {
		note("failed: %v", err)
		fmt.Fprintln(os.Stderr, "ghost:", err)
		os.Exit(1)
	}
	note("read %d bytes", got)
	fmt.Println(got)
	if len(os.Args) == 4 {
		for i := 0; i < 1200; i++ { // two minutes of heartbeat
			if f, err := os.OpenFile(os.Args[3], os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				fmt.Fprintln(f, i)
				f.Close()
			}
			time.Sleep(100 * time.Millisecond)
		}
		return
	}
	time.Sleep(60 * time.Second)
}
