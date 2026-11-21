package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/evtlog"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Ways of reading a bait that the audit rule used to miss. These need the
// real Security log, so they run with the other admin tests in CI.

// The test binary doubles as the reader: ABA_ITEST_READ=<how> <binary> <path>.
func TestMain(m *testing.M) {
	if how := os.Getenv("ABA_ITEST_READ"); how != "" {
		os.Exit(readHelper(how, os.Args[len(os.Args)-1]))
	}
	os.Exit(m.Run())
}

func readHelper(how, path string) int {
	switch how {
	case "map": // open for execute only, map it, read the mapping: never asks for read access
		us, err := windows.NewNTUnicodeString(`\??\` + path)
		if err != nil {
			return 1
		}
		oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: us, Attributes: 0x40}
		var iosb windows.IO_STATUS_BLOCK
		var h windows.Handle
		const fileExecute, nonDirectory, syncIO = 0x20, 0x40, 0x20
		if windows.NtCreateFile(&h, fileExecute|windows.SYNCHRONIZE, &oa, &iosb, nil, 0, 7, 1, nonDirectory|syncIO, 0, 0); h == 0 {
			return 2
		}
		nt := windows.NewLazySystemDLL("ntdll.dll")
		var sec windows.Handle
		if r, _, _ := nt.NewProc("NtCreateSection").Call(uintptr(unsafe.Pointer(&sec)), 0x8|0x1, 0, 0, windows.PAGE_EXECUTE, 0x8000000, uintptr(h)); r != 0 {
			return 3
		}
		var base unsafe.Pointer
		var size uintptr
		if r, _, _ := nt.NewProc("NtMapViewOfSection").Call(uintptr(sec), ^uintptr(0), uintptr(unsafe.Pointer(&base)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 2, 0, windows.PAGE_EXECUTE); r != 0 {
			return 4
		}
		fmt.Print(string(unsafe.Slice((*byte)(base), 7)))
		return 0
	}
	return 9
}

// watchBait turns auditing on, puts ABA's audit rule on a new file and
// returns the 4663 events for anything with that file's identity, whatever
// name it was opened by.
func watchBait(t *testing.T) (bait string, events chan *evtlog.ObjectAccess) {
	t.Helper()
	orig, err := winsec.FileSystemAudit()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { winsec.SetFileSystemAudit(orig) })
	if _, err := winsec.EnsureFileSystemAudit(); err != nil {
		t.Fatal(err)
	}
	bait = filepath.Join(t.TempDir(), "passwords.txt")
	os.WriteFile(bait, []byte("hunter2 and more"), 0o644)
	if err := winsec.SetBaitAudit(bait); err != nil {
		t.Fatal(err)
	}
	id, ok := paths.FileID(bait)
	if !ok {
		t.Fatal("no file identity for the bait")
	}
	sub, err := evtlog.Subscribe("Security", evtlog.BaitQuery, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sub.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	events = make(chan *evtlog.ObjectAccess, 16)
	go sub.Run(ctx, func(x string) {
		e, err := evtlog.Parse(x)
		if err != nil {
			return
		}
		oa, ok := e.AsObjectAccess()
		if !ok {
			return
		}
		if got, ok := paths.FileID(oa.ObjectName); ok && got == id {
			events <- oa
		}
	})
	time.Sleep(300 * time.Millisecond)
	return bait, events
}

// A file opened for execute only can be mapped and read without read access
// ever being asked for. The audit rule covers "execute" for that reason.
func TestExecuteOnlyMappingIsAudited(t *testing.T) {
	requireAdmin(t)
	bait, events := watchBait(t)
	c := exec.Command(os.Args[0], bait)
	c.Env = append(os.Environ(), "ABA_ITEST_READ=map")
	out, err := c.Output()
	if err != nil || string(out) != "hunter2" {
		t.Fatalf("the helper should have read the bait through an execute-only mapping: %q, %v", out, err)
	}
	select {
	case oa := <-events:
		t.Logf("audited: %s by pid %d, access 0x%x", oa.ObjectName, oa.ProcessID, oa.AccessMask)
		if int(oa.ProcessID) != c.Process.Pid || !winsec.AccessMaskIsRead(oa.AccessMask) {
			t.Fatalf("unexpected event: %+v", oa)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a bait was read through an execute-only mapping and Windows logged nothing")
	}
}

// A hard link is a second name for the same file. Reading the bait through
// one must still produce an event that leads back to the bait: ABA recognises
// the file by its identity, not by the name in the event.
func TestReadThroughAHardLinkIsRecognised(t *testing.T) {
	requireAdmin(t)
	bait, events := watchBait(t)
	link := filepath.Join(filepath.Dir(bait), "cache.dat")
	if err := os.Link(bait, link); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/c", "type", link).CombinedOutput(); err != nil {
		t.Fatalf("type: %v %s", err, out)
	}
	select {
	case oa := <-events:
		t.Logf("audited as %s (the bait is %s)", oa.ObjectName, bait)
		if !strings.HasSuffix(strings.ToLower(oa.ProcessName), `\cmd.exe`) || !winsec.AccessMaskIsRead(oa.AccessMask) {
			t.Fatalf("unexpected event: %+v", oa)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a bait was read through a hard link and no event led back to it")
	}
}
