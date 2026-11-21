package install

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// testEntry is an app entry under the current user's registry and in a temp
// folder: the real thing needs administrator rights and would show up in
// Windows' list.
func testEntry(t *testing.T) appEntry {
	t.Helper()
	dir := t.TempDir()
	prog := filepath.Join(dir, "File Access Monitor")
	if err := os.MkdirAll(filepath.Join(prog, "updates"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Two "copies of ABA" of 3 KB and 2 KB, and a download that mustn't be counted.
	for name, size := range map[string]int{"aba.exe": 3 << 10, "famsvc.exe": 2 << 10, `updates\aba-v9.exe`: 64 << 10} {
		if err := os.WriteFile(filepath.Join(prog, name), make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := appEntry{
		root:    registry.CURRENT_USER,
		keyPath: fmt.Sprintf(`Software\ABA-test-%d-%s`, os.Getpid(), t.Name()),
		menuDir: filepath.Join(dir, "Start Menu", "Programs"),
		exe:     filepath.Join(prog, "aba.exe"),
		dir:     prog,
	}
	t.Cleanup(func() { registry.DeleteKey(e.root, e.keyPath) })
	return e
}

func readKey(t *testing.T, e appEntry) (map[string]string, map[string]uint64) {
	t.Helper()
	k, err := registry.OpenKey(e.root, e.keyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("the Installed apps entry is missing: %v", err)
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		t.Fatal(err)
	}
	strs, nums := map[string]string{}, map[string]uint64{}
	for _, n := range names {
		if s, _, err := k.GetStringValue(n); err == nil {
			strs[n] = s
		} else if v, _, err := k.GetIntegerValue(n); err == nil {
			nums[n] = v
		}
	}
	return strs, nums
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestRegisterAppWritesTheEntryAndTheShortcut(t *testing.T) {
	e := testEntry(t)
	if err := e.register("v1.2.3"); err != nil {
		t.Fatal(err)
	}
	strs, nums := readKey(t, e)
	for name, want := range map[string]string{
		"DisplayName":          "A Better Antivirus",
		"DisplayVersion":       "1.2.3",
		"InstallLocation":      e.dir,
		"DisplayIcon":          e.exe,
		"UninstallString":      `"` + e.exe + `" uninstall --elevated-pause`,
		"QuietUninstallString": `"` + e.exe + `" uninstall --yes`,
	} {
		if strs[name] != want {
			t.Errorf("%s = %q, want %q", name, strs[name], want)
		}
	}
	if strs["Publisher"] == "" || strs["URLInfoAbout"] == "" {
		t.Errorf("Publisher and URLInfoAbout should be filled in: %v", strs)
	}
	if len(strs["InstallDate"]) != 8 {
		t.Errorf("InstallDate = %q, want YYYYMMDD", strs["InstallDate"])
	}
	if nums["NoModify"] != 1 || nums["NoRepair"] != 1 {
		t.Errorf("NoModify/NoRepair = %d/%d, want 1/1", nums["NoModify"], nums["NoRepair"])
	}
	if nums["EstimatedSize"] != 5 {
		t.Errorf("EstimatedSize = %d KB, want 5 (the two programs, not the downloaded update)", nums["EstimatedSize"])
	}

	// The shortcut is named after the app, sits in the Start menu folder and
	// opens the installed aba.exe (asked of Windows, the way the Start menu does).
	target, err := shortcutTarget(filepath.Join(e.menuDir, "A Better Antivirus.lnk"))
	if err != nil {
		t.Fatalf("the Start menu shortcut can't be read: %v", err)
	}
	if !paths.Same(paths.Long(target), paths.Long(e.exe)) {
		t.Errorf("the shortcut opens %s, want %s", target, e.exe)
	}
}

// shortcutTarget loads a .lnk and returns the program it starts.
func shortcutTarget(lnk string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	}
	var link *comObject
	hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidShellLink)), 0, windows.CLSCTX_INPROC_SERVER,
		uintptr(unsafe.Pointer(&iidIShellLinkW)), uintptr(unsafe.Pointer(&link)))
	if int32(hr) < 0 || link == nil {
		return "", fmt.Errorf("COM error 0x%08X", uint32(hr))
	}
	defer link.call(comRelease)
	var file *comObject
	if err := link.call(comQueryInterface, uintptr(unsafe.Pointer(&iidIPersistFile)), uintptr(unsafe.Pointer(&file))); err != nil {
		return "", err
	}
	defer file.call(comRelease)
	const persistFileLoad, shellLinkGetPath = 5, 3
	p, err := windows.UTF16PtrFromString(lnk)
	if err != nil {
		return "", err
	}
	if err := file.call(persistFileLoad, uintptr(unsafe.Pointer(p)), 0); err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	if err := link.call(shellLinkGetPath, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}

func TestRegisterAppTwiceIsFine(t *testing.T) {
	e := testEntry(t)
	for i := 0; i < 2; i++ {
		if err := e.register("v1.0.0"); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
}

func TestRefreshAppAfterAnUpdate(t *testing.T) {
	e := testEntry(t)
	if err := e.register("v1.0.0"); err != nil {
		t.Fatal(err)
	}
	// Installed a while ago, and the owner removed the shortcut since.
	k, err := registry.OpenKey(e.root, e.keyPath, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	k.SetStringValue("InstallDate", "20200102")
	k.Close()
	if err := os.Remove(e.shortcut()); err != nil {
		t.Fatal(err)
	}

	if err := e.refresh("v1.1.0"); err != nil {
		t.Fatal(err)
	}
	strs, _ := readKey(t, e)
	if strs["DisplayVersion"] != "1.1.0" {
		t.Errorf("DisplayVersion = %q after the update, want 1.1.0", strs["DisplayVersion"])
	}
	if strs["InstallDate"] != "20200102" {
		t.Errorf("InstallDate = %q: an update must not change it", strs["InstallDate"])
	}
	if exists(e.shortcut()) {
		t.Error("an update put back a shortcut the owner had deleted")
	}
}

func TestRefreshAppGivesAnOlderInstallItsEntry(t *testing.T) {
	// An install from before ABA listed itself: the first update adds both.
	e := testEntry(t)
	if err := e.refresh("v2.0.0"); err != nil {
		t.Fatal(err)
	}
	strs, _ := readKey(t, e)
	if strs["DisplayVersion"] != "2.0.0" {
		t.Errorf("DisplayVersion = %q, want 2.0.0", strs["DisplayVersion"])
	}
	if !exists(e.shortcut()) {
		t.Error("no Start menu shortcut after the update")
	}
}

func TestUnregisterAppRemovesBoth(t *testing.T) {
	e := testEntry(t)
	if err := e.register("v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := e.unregister(); err != nil {
		t.Fatal(err)
	}
	if e.registered() {
		t.Error("the Installed apps entry is still there")
	}
	if exists(e.shortcut()) {
		t.Error("the Start menu shortcut is still there")
	}
	// Uninstalling something that was never listed (an older install) is not an error.
	if err := e.unregister(); err != nil {
		t.Errorf("second unregister: %v", err)
	}
}
