package netguard

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// windowsAppID is Windows' own helper for a program's WFP app ID, which ABA
// doesn't ship (see appIDFor). Only the tests call it, to check that ABA's
// name for a program is the one WFP itself uses.
func windowsAppID(t *testing.T, file string) string {
	t.Helper()
	proc := windows.NewLazySystemDLL("fwpuclnt.dll").NewProc("FwpmGetAppIdFromFileName0")
	freeMem := windows.NewLazySystemDLL("fwpuclnt.dll").NewProc("FwpmFreeMemory0")
	p, err := windows.UTF16PtrFromString(file)
	if err != nil {
		t.Fatal(err)
	}
	var blob *struct {
		Size uint32
		Data *uint16
	}
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&blob))); r != 0 {
		t.Fatalf("FwpmGetAppIdFromFileName0(%s): %v", file, syscall.Errno(r))
	}
	defer freeMem.Call(uintptr(unsafe.Pointer(&blob)))
	return windows.UTF16ToString(unsafe.Slice(blob.Data, blob.Size/2))
}

func TestAppIDIsWindowsOwn(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	files := []string{self, filepath.Join(os.Getenv("SystemRoot"), `System32\svchost.exe`), filepath.Join(os.Getenv("SystemRoot"), "explorer.exe")}
	// The same program by its 8.3 short name, where the drive keeps those.
	if p, err := windows.UTF16PtrFromString(self); err == nil {
		buf := make([]uint16, 1024)
		if n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf))); err == nil && n > 0 {
			files = append(files, windows.UTF16ToString(buf[:n]))
		}
	}
	for _, f := range files {
		got, err := appIDFor(f)
		if err != nil {
			t.Fatalf("appIDFor(%s): %v", f, err)
		}
		// What ABA asked Windows for before: its helper, given the long
		// name (handed a short name it keeps it, and WFP never matches).
		if want := windowsAppID(t, paths.Long(f)); got != want {
			t.Errorf("appIDFor(%s)\n got %q\nwant %q (Windows' own)", f, got, want)
		}
		t.Logf("%s -> %s", f, got)
	}
}

func TestAppIDMissingFile(t *testing.T) {
	if _, err := appIDFor(filepath.Join(t.TempDir(), "gone.exe")); err == nil {
		t.Error("an app ID for a file that doesn't exist")
	}
}
