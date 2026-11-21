package procinfo

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
)

func TestInjectedCodeCleanWindowsProcess(t *testing.T) {
	cmd := exec.Command(`C:\Windows\System32\PING.EXE`, "-n", "6", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(500 * time.Millisecond)
	if d, found := InjectedCode(uint32(cmd.Process.Pid)); found {
		t.Fatalf("clean ping.exe flagged: %s", d)
	}
	// Whatever explorer looks like on this machine (informational: shell
	// extensions and overlays vary).
	if snap, err := Snapshot(); err == nil {
		for pid, e := range snap {
			if strings.EqualFold(e.Exe, "explorer.exe") {
				d, found := InjectedCode(pid)
				t.Logf("explorer.exe pid %d: found=%v %s", pid, found, d)
			}
		}
	}
}

func TestInjectedCodeFindsPrivateExecutableMemory(t *testing.T) {
	pid := uint32(os.Getpid())
	if d, found := InjectedCode(pid); found {
		t.Logf("note: test process already has unbacked code: %s", d)
	}
	size := uintptr(128 << 10)
	addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	mz := []byte("MZ")
	if err := windows.WriteProcessMemory(windows.CurrentProcess(), addr, &mz[0], 2, nil); err != nil {
		t.Fatal(err)
	}
	var old uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &old); err != nil {
		t.Fatal(err)
	}
	d, found := InjectedCode(pid)
	if !found || !strings.Contains(d, "whole program") {
		t.Fatalf("injected region not found: %q", d)
	}
	t.Log(d)
}

func TestInjectedCodeIgnoresSmallHooks(t *testing.T) {
	pid := uint32(os.Getpid())
	// Ten 4 KB trampolines and one 64 KB thunk block, like explorer.exe with
	// a few shell extensions and overlays: not an injected program.
	var allocs []uintptr
	for _, size := range []uintptr{64 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10} {
		addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READ)
		if err != nil {
			t.Fatal(err)
		}
		allocs = append(allocs, addr)
	}
	defer func() {
		for _, a := range allocs {
			windows.VirtualFree(a, 0, windows.MEM_RELEASE)
		}
	}()
	if d, found := InjectedCode(pid); found {
		t.Fatalf("small hooks flagged as injection: %s", d)
	}
}

// DLL sideloading, for real: a Windows program copied into a folder together
// with a DLL it loads by name picks that DLL up from next to itself.
func TestSideLoadedFindsTheDLLNextToTheProgram(t *testing.T) {
	sys := os.Getenv("SystemRoot") + `\System32\`
	dir := t.TempDir()
	for _, f := range []string{"PING.EXE", "IPHLPAPI.DLL"} {
		b, err := os.ReadFile(sys + f)
		if err != nil {
			t.Skip(err)
		}
		os.WriteFile(dir+`\`+f, b, 0o755)
	}
	image := dir + `\PING.EXE`
	cmd := exec.Command(image, "-n", "8", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(700 * time.Millisecond)
	pid := uint32(cmd.Process.Pid)

	var asked []string
	dll, found := SideLoaded(pid, image, func(p string) bool { asked = append(asked, p); return false })
	if !found || !strings.EqualFold(dll, dir+`\IPHLPAPI.DLL`) {
		t.Skipf("ping didn't load the DLL from its own folder here (found=%v %q, asked about %v)", found, dll, asked)
	}
	// Only DLLs from the program's own folder are looked at: nothing from Windows.
	for _, p := range asked {
		if !strings.HasPrefix(strings.ToLower(p), strings.ToLower(dir)) {
			t.Fatalf("looked at a DLL outside the program's folder: %s", p)
		}
	}
	// Properly signed, it's not sideloading.
	if dll, found := SideLoaded(pid, image, func(string) bool { return true }); found {
		t.Fatalf("a signed DLL next to the program was reported: %s", dll)
	}
	// The real one, where Windows keeps it: everything next to it is signed.
	plain := exec.Command(sys+"PING.EXE", "-n", "4", "127.0.0.1")
	if err := plain.Start(); err == nil {
		defer func() { plain.Process.Kill(); plain.Wait() }()
		time.Sleep(400 * time.Millisecond)
		if dll, found := SideLoaded(uint32(plain.Process.Pid), sys+"PING.EXE", func(p string) bool { return authenticode.Verify(p).Valid }); found {
			t.Fatalf("the real ping.exe in System32 was reported as sideloaded: %s", dll)
		}
	}
}
