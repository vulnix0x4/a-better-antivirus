package install

// ABA's entry in Windows' "Installed apps" list and its Start menu shortcut.
//
// ABA writes and removes both itself, so they exist whichever way it was
// installed (the setup program, the PowerShell command, `aba install`) and
// `aba uninstall` always takes them away again. Uninstalling from Windows'
// list simply runs `aba uninstall`.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// AppName is what ABA is called in Windows' "Installed apps" list and in the
// Start menu. The service, the program folder and the data folder keep their
// low-profile names (see package paths); this is the one place a person goes
// looking for ABA by name.
const AppName = "A Better Antivirus"

const (
	appPublisher = "A Better Antivirus contributors"
	appURL       = "https://github.com/vulnix0x4/a-better-antivirus"

	// Windows lists whatever has a key under here. The key's own name is never shown.
	uninstallKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + paths.ServiceName
)

// appEntry is where the two things live. Tests point it somewhere harmless.
type appEntry struct {
	root    registry.Key
	keyPath string
	menuDir string // the Start menu's Programs folder
	exe     string // the installed aba.exe
	dir     string // the program folder
}

func systemAppEntry() (appEntry, error) {
	// The Start menu everyone on this PC shares: like Program Files, only
	// administrators can change it, so nothing running as you can repoint the
	// shortcut at something else.
	menu, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil || menu == "" {
		return appEntry{}, fmt.Errorf("find the Start menu folder: %v", err)
	}
	return appEntry{
		root:    registry.LOCAL_MACHINE,
		keyPath: uninstallKeyPath,
		menuDir: menu,
		exe:     paths.InstalledCLI(),
		dir:     paths.InstallDir(),
	}, nil
}

// appSteps put ABA where people look for an installed program: Windows'
// "Installed apps" list and the Start menu. removeAppSteps undo it on uninstall.
func appSteps(version string) []Step {
	return []Step{{Name: "Adding ABA to Installed apps and the Start menu", Soft: true, Run: func() (string, error) {
		return "listed as \"" + AppName + "\"", RegisterApp(version)
	}}}
}

func removeAppSteps() []Step {
	return []Step{{Name: "Removing ABA from Installed apps and the Start menu", Soft: true, Run: func() (string, error) {
		return "", UnregisterApp()
	}}}
}

// RegisterApp lists ABA under Installed apps and adds the Start menu shortcut
// (which opens the dashboard). Safe to repeat.
func RegisterApp(version string) error {
	e, err := systemAppEntry()
	if err != nil {
		return err
	}
	return e.register(version)
}

// RefreshApp runs after an update: it puts the new version number in the
// Installed apps entry. An install from before ABA had such an entry gets the
// entry and the shortcut now. A shortcut you deleted yourself stays deleted.
func RefreshApp(version string) error {
	e, err := systemAppEntry()
	if err != nil {
		return err
	}
	return e.refresh(version)
}

// UnregisterApp removes the Installed apps entry and the shortcut.
func UnregisterApp() error {
	e, err := systemAppEntry()
	if err != nil {
		return err
	}
	return e.unregister()
}

func (e appEntry) shortcut() string { return filepath.Join(e.menuDir, AppName+".lnk") }

// ReportsName is the Start menu entry that opens every report ABA wrote
// about a program it caught (`aba reports`).
const ReportsName = "ABA reports"

func (e appEntry) reportsShortcut() string { return filepath.Join(e.menuDir, ReportsName+".lnk") }

// reportsMade is set on the Installed apps entry once ABA has made the
// reports shortcut, so an update doesn't put it back after you deleted it.
const reportsMade = "ABAReportsShortcut"

func (e appEntry) addReportsShortcut() error {
	if err := createShortcut(e.reportsShortcut(), e.exe, "reports", e.dir, "Every program ABA caught, and what it did, in your web browser"); err != nil {
		return err
	}
	k, err := registry.OpenKey(e.root, e.keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(reportsMade, 1)
}

func (e appEntry) registered() bool {
	k, err := registry.OpenKey(e.root, e.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func (e appEntry) register(version string) error {
	if err := e.writeKey(version); err != nil {
		return err
	}
	if err := os.MkdirAll(e.menuDir, 0o755); err != nil {
		return err
	}
	if err := createShortcut(e.shortcut(), e.exe, "", e.dir, "See whether you're protected and what touched your baits"); err != nil {
		return err
	}
	return e.addReportsShortcut()
}

func (e appEntry) refresh(version string) error {
	if !e.registered() {
		return e.register(version)
	}
	if err := e.writeKey(version); err != nil {
		return err
	}
	// An install from before there were reports gets their shortcut now, once.
	k, err := registry.OpenKey(e.root, e.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	_, _, err = k.GetIntegerValue(reportsMade)
	k.Close()
	if err == nil {
		return nil
	}
	if err := os.MkdirAll(e.menuDir, 0o755); err != nil {
		return err
	}
	return e.addReportsShortcut()
}

// UninstallCommand is what Windows runs when you pick Uninstall in its list.
// It asks before removing anything and keeps its window open at the end, so
// you can read what happened (--elevated-pause, the same flag ABA gives itself
// when it reopens as administrator). The quiet form is for scripts.
func UninstallCommand(exe string, quiet bool) string {
	if quiet {
		return `"` + exe + `" uninstall --yes`
	}
	return `"` + exe + `" uninstall --elevated-pause`
}

func (e appEntry) writeKey(version string) error {
	k, _, err := registry.CreateKey(e.root, e.keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for name, v := range map[string]string{
		"DisplayName":          AppName,
		"DisplayVersion":       strings.TrimPrefix(version, "v"),
		"Publisher":            appPublisher,
		"URLInfoAbout":         appURL,
		"InstallLocation":      e.dir,
		"DisplayIcon":          e.exe,
		"UninstallString":      UninstallCommand(e.exe, false),
		"QuietUninstallString": UninstallCommand(e.exe, true),
	} {
		if err := k.SetStringValue(name, v); err != nil {
			return err
		}
	}
	// Changing settings and repairing are `aba configure` and `aba doctor --fix`:
	// there's nothing for Windows' Modify and Repair buttons to run.
	for _, name := range []string{"NoModify", "NoRepair"} {
		if err := k.SetDWordValue(name, 1); err != nil {
			return err
		}
	}
	if kb := dirSizeKB(e.dir); kb > 0 {
		if err := k.SetDWordValue("EstimatedSize", kb); err != nil {
			return err
		}
	}
	// The day ABA was first listed; an update or a repair doesn't move it.
	if _, _, err := k.GetStringValue("InstallDate"); err != nil {
		if err := k.SetStringValue("InstallDate", time.Now().Format("20060102")); err != nil {
			return err
		}
	}
	return nil
}

func (e appEntry) unregister() error {
	var errs []error
	if err := registry.DeleteKey(e.root, e.keyPath); err != nil && !errors.Is(err, registry.ErrNotExist) {
		errs = append(errs, err)
	}
	for _, lnk := range []string{e.shortcut(), e.reportsShortcut()} {
		if err := os.Remove(lnk); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// dirSizeKB adds up the files directly in dir (the program folder holds just
// the two copies of ABA; downloaded updates in its subfolder don't count).
func dirSizeKB(dir string) uint32 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, en := range entries {
		if info, err := en.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return uint32(total / 1024)
}

// ---- writing a .lnk ----
//
// Windows only offers this through COM (IShellLink + IPersistFile). The two
// interfaces are called through their method tables directly, which avoids
// pulling in a COM library for one shortcut.

var (
	clsidShellLink  = windows.GUID{Data1: 0x00021401, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIShellLinkW  = windows.GUID{Data1: 0x000214F9, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIPersistFile = windows.GUID{Data1: 0x0000010B, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}

	procCoCreateInstance = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")
)

// Positions in the method tables (after IUnknown's three).
const (
	comQueryInterface = 0
	comRelease        = 2

	shellLinkSetDescription      = 7
	shellLinkSetWorkingDirectory = 9
	shellLinkSetArguments        = 11
	shellLinkSetPath             = 20

	persistFileSave = 6
)

// comObject is a COM interface pointer: a pointer to a pointer to its method table.
type comObject struct {
	vtbl *[24]uintptr
}

// call invokes a method by its position in the table. The directive makes
// the compiler keep pointers passed as uintptr alive, and in place, for the
// length of the call (as it does for syscall.Syscall).
//
//go:uintptrescapes
func (o *comObject) call(method int, args ...uintptr) error {
	all := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	hr, _, _ := syscall.SyscallN(o.vtbl[method], all...)
	if int32(hr) < 0 {
		return fmt.Errorf("COM error 0x%08X", uint32(hr))
	}
	return nil
}

// createShortcut writes a shortcut at lnk that starts target with args in workDir.
func createShortcut(lnk, target, args, workDir, description string) error {
	// COM belongs to the thread that initialised it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	} else if code, ok := err.(syscall.Errno); ok && uint32(code) == 1 {
		// S_FALSE: this thread had COM started already. It still counts as a
		// start, so it gets its matching stop.
		defer windows.CoUninitialize()
	} else if !ok || uint32(code) != 0x80010106 {
		// (0x80010106, RPC_E_CHANGED_MODE: started by someone else in another
		// mode, which works just as well for this.)
		return fmt.Errorf("create shortcut: start COM: %w", err)
	}

	var link *comObject
	hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidShellLink)), 0, windows.CLSCTX_INPROC_SERVER,
		uintptr(unsafe.Pointer(&iidIShellLinkW)), uintptr(unsafe.Pointer(&link)))
	if int32(hr) < 0 || link == nil {
		return fmt.Errorf("create shortcut: COM error 0x%08X", uint32(hr))
	}
	defer link.call(comRelease)

	for _, set := range []struct {
		method int
		value  string
	}{{shellLinkSetPath, target}, {shellLinkSetArguments, args}, {shellLinkSetWorkingDirectory, workDir}, {shellLinkSetDescription, description}} {
		p, err := windows.UTF16PtrFromString(set.value)
		if err != nil {
			return fmt.Errorf("create shortcut: %w", err)
		}
		if err := link.call(set.method, uintptr(unsafe.Pointer(p))); err != nil {
			return fmt.Errorf("create shortcut: %w", err)
		}
	}

	var file *comObject
	if err := link.call(comQueryInterface, uintptr(unsafe.Pointer(&iidIPersistFile)), uintptr(unsafe.Pointer(&file))); err != nil || file == nil {
		return fmt.Errorf("create shortcut: %v", err)
	}
	defer file.call(comRelease)
	p, err := windows.UTF16PtrFromString(lnk)
	if err != nil {
		return fmt.Errorf("create shortcut: %w", err)
	}
	if err := file.call(persistFileSave, uintptr(unsafe.Pointer(p)), 1); err != nil {
		return fmt.Errorf("create shortcut %s: %w", lnk, err)
	}
	return nil
}
