package install

// The desktop app (aba-app.exe, cmd/aba-app): installed next to aba.exe, in
// the Start menu as "ABA".
//
// Like everything else, ABA installs and removes it itself, whichever way ABA
// came onto the PC: ABA-Setup.exe, install.ps1 and a release's download put
// aba-app.exe next to the aba.exe that runs `aba install`, and an update
// brings the new one along (package update). A PC that has none (updated by
// a version from before the app, or set up from a bare aba.exe) gets its
// version's from the release, checked against the signed checksum list
// (update.KeepApp, run by the service).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// AppShortcutName is the app's Start menu entry.
const AppShortcutName = "ABA"

// AppShortcutArgs is what it passes the app.
const AppShortcutArgs = "--elevate"

// appMade is set on the Installed apps entry once ABA has made the app's
// shortcut, so an update doesn't put it back after you deleted it.
const appMade = "ABAAppShortcut"

func (e appEntry) appShortcut() string { return filepath.Join(e.menuDir, AppShortcutName+".lnk") }

func (e appEntry) addAppShortcut() error {
	// The app asks for administrator rights itself as it opens (--elevate:
	// one UAC prompt, before any window; declined, it shows its locked
	// view). Not the shortcut's "run as administrator" flag: declined, that
	// opens nothing at all.
	if err := createShortcut(e.appShortcut(), e.app, AppShortcutArgs, e.dir, "Open ABA: whether you're protected, and anything it caught"); err != nil {
		return err
	}
	k, err := registry.OpenKey(e.root, e.keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(appMade, 1)
}

// appShortcutOnce makes the app's shortcut if ABA never made it before, and
// takes away the two entries from before the app (an install that had them
// gets the one "ABA" instead). Not listed in Installed apps yet (a first
// install, mid-way): nothing to do, the listing makes it.
func (e appEntry) appShortcutOnce() error {
	if !fileExists(e.app) {
		return nil
	}
	k, err := registry.OpenKey(e.root, e.keyPath, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	_, _, err = k.GetIntegerValue(appMade)
	k.Close()
	if err != nil {
		if err := os.MkdirAll(e.menuDir, 0o755); err != nil {
			return err
		}
		if err := e.addAppShortcut(); err != nil {
			return err
		}
	}
	return e.removeTerminalShortcuts()
}

// AppWanted reports whether the app belongs on this PC: it wasn't left out
// on purpose.
func AppWanted() bool { return !fileExists(paths.AppOffFile()) }

// InstallApp puts the app at src in place (a copy that's open is moved
// aside, see CopyFile) and adds its Start menu entry if ABA never made one.
// Whoever calls it has checked src: it came with this aba.exe, or its hash is
// in a release's signed checksum list.
func InstallApp(src string) error {
	if err := os.MkdirAll(paths.InstallDir(), 0o755); err != nil {
		return err
	}
	if err := CopyFile(src, paths.InstalledApp()); err != nil {
		return err
	}
	os.Remove(paths.AppOffFile())
	e, err := systemAppEntry()
	if err != nil {
		return err
	}
	return e.appShortcutOnce()
}

// installApp installs the app that came with this aba.exe (next to it), or
// leaves it out when install.ps1 was told to (aba-app.off next to it). With
// neither, the install keeps what it has.
func installApp(self string) (string, error) {
	dir := filepath.Dir(self)
	if fileExists(filepath.Join(dir, paths.AppOffName)) && !paths.Same(dir, paths.InstallDir()) {
		return "left out, as asked", leaveAppOut()
	}
	src := filepath.Join(dir, paths.AppExe)
	switch {
	case fileExists(src) && !paths.Same(src, paths.InstalledApp()):
		if err := InstallApp(src); err != nil {
			return "", err
		}
		return "in the Start menu as \"" + AppShortcutName + "\"", nil
	case fileExists(paths.InstalledApp()):
		return "in the Start menu as \"" + AppShortcutName + "\"", nil
	case !AppWanted():
		return "left out, as asked earlier", nil
	}
	// A bare aba.exe: the service fetches its release's app (update.KeepApp).
	return "not included in this copy of aba.exe", nil
}

// leaveAppOut removes the app and its shortcut and remembers that, so
// updates don't bring it back.
func leaveAppOut() error {
	if err := os.MkdirAll(paths.InstallDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(paths.AppOffFile(), []byte("The ABA app was left out on purpose: updates don't install it. Delete this file, or run ABA-Setup.exe, to get it back.\r\n"), 0o644); err != nil {
		return err
	}
	closeApp()
	var errs []error
	if fileExists(paths.InstalledApp()) {
		old := fmt.Sprintf("%s.old-%d", paths.InstalledApp(), time.Now().UnixNano())
		if err := os.Rename(paths.InstalledApp(), old); err != nil {
			errs = append(errs, err)
		} else {
			scheduleDelete(old)
		}
	}
	if e, err := systemAppEntry(); err == nil {
		if err := os.Remove(e.appShortcut()); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// closeApp ends the installed app if it's open (it is about to be removed).
// Its WebView2 processes end with it.
func closeApp() {
	snap, err := procinfo.Snapshot()
	if err != nil {
		return
	}
	n := 0
	for pid := range snap {
		if img, err := procinfo.ImagePath(pid); err == nil && isApp(img) {
			procinfo.Kill(pid)
			n++
		}
	}
	if n > 0 {
		time.Sleep(time.Second)
	}
}

// removeAppData deletes the app's WebView2 profile (%LocalAppData%\ABA\webview,
// see appsec.WebViewDir) for every person on this PC who may have opened it.
// It holds nothing ABA needs: a cache and the page's own storage.
func removeAppData() (string, error) {
	closeApp()
	var errs []error
	n := 0
	for _, dir := range localAppDataDirs() {
		removed, err := removeWebViewProfile(dir)
		if err != nil {
			errs = append(errs, err)
		}
		if removed {
			n++
		}
	}
	if n == 0 {
		return "there was none", errors.Join(errs...)
	}
	return fmt.Sprintf("%d profile(s)", n), errors.Join(errs...)
}

// removeWebViewProfile deletes <localAppData>\ABA\webview, and ABA's folder
// there once it's empty. That folder belongs to the person, who can put a
// junction or link anywhere in it: an administrator deleting through one
// would delete whatever it points at. os.Root refuses to leave localAppData,
// whatever is in the way.
func removeWebViewProfile(localAppData string) (bool, error) {
	root, err := os.OpenRoot(localAppData)
	if err != nil {
		return false, nil // no such profile folder
	}
	defer root.Close()
	profile := filepath.Join(paths.ProductName, "webview")
	if _, err := root.Lstat(profile); err != nil {
		return false, nil
	}
	// The browser processes can take a moment to end after the app.
	for try := 0; ; try++ {
		err = root.RemoveAll(profile)
		if err == nil || try == 9 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", filepath.Join(localAppData, profile), err)
	}
	root.Remove(paths.ProductName) // only if nothing else is in it
	return true, nil
}

// localAppDataDirs lists where each person's %LocalAppData% is: the
// protected person's as setup found it, and the usual place in every
// person's profile Windows knows of (from the registry: no folder on the PC
// is listed or searched).
func localAppDataDirs() []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[strings.ToLower(filepath.Clean(p))] {
			return
		}
		seen[strings.ToLower(filepath.Clean(p))] = true
		out = append(out, p)
	}
	if cfg, err := config.LoadConfig(); err == nil {
		add(cfg.User.LocalAppData)
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return out
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") { // people, not SYSTEM and the service accounts
			continue
		}
		pk, err := registry.OpenKey(k, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dir, _, err := pk.GetStringValue("ProfileImagePath")
		pk.Close()
		if err != nil || dir == "" {
			continue
		}
		if x, err := registry.ExpandString(dir); err == nil {
			dir = x
		}
		add(filepath.Join(dir, "AppData", "Local"))
	}
	return out
}

// isApp: img is the installed app, or a copy an update moved aside while it
// was open (aba-app.exe.old-<n>, see CopyFile), which is still running.
func isApp(img string) bool {
	base := strings.ToLower(filepath.Base(img))
	return paths.Same(filepath.Dir(img), paths.InstallDir()) &&
		(base == strings.ToLower(paths.AppExe) || strings.HasPrefix(base, strings.ToLower(paths.AppExe)+".old"))
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
