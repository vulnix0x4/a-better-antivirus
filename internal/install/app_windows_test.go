package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// withApp is a test entry whose program folder holds the desktop app too.
func withApp(t *testing.T) appEntry {
	t.Helper()
	e := testEntry(t)
	e.app = filepath.Join(e.dir, "aba-app.exe")
	if err := os.WriteFile(e.app, []byte("app"), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRegisterAppAddsTheAppShortcut(t *testing.T) {
	e := withApp(t)
	if err := e.register("v1.0.0"); err != nil {
		t.Fatal(err)
	}
	lnk := filepath.Join(e.menuDir, "ABA.lnk")
	target, err := shortcutTarget(lnk)
	if err != nil {
		t.Fatalf("no ABA shortcut: %v", err)
	}
	if !paths.Same(paths.Long(target), paths.Long(e.app)) {
		t.Errorf("the ABA shortcut opens %s, want %s", target, e.app)
	}
	if args, _ := shortcutArgs(lnk); args != "" {
		t.Errorf("the ABA shortcut passes %q, want nothing", args)
	}
	// It is the only one: no terminal dashboard, no reports in the browser.
	if exists(e.shortcut()) || exists(e.reportsShortcut()) {
		t.Error("with the app, the Start menu still has the terminal shortcuts")
	}

	if err := e.unregister(); err != nil {
		t.Fatal(err)
	}
	if exists(lnk) {
		t.Error("uninstall left the ABA shortcut")
	}
}

func TestRegisterWithoutTheAppHasNoAppShortcut(t *testing.T) {
	e := withApp(t)
	if err := e.register("v1.0.0"); err != nil {
		t.Fatal(err)
	}
	// Left out afterwards (install.ps1 with ABA_NO_APP): a repair takes the
	// entry away instead of leaving one that opens nothing.
	os.Remove(e.app)
	if err := e.register("v1.0.0"); err != nil {
		t.Fatal(err)
	}
	if exists(e.appShortcut()) {
		t.Error("an ABA shortcut with no app behind it")
	}
	// ...and the terminal dashboard and the reports come back instead.
	if target, _ := shortcutTarget(e.shortcut()); !paths.Same(paths.Long(target), paths.Long(e.exe)) {
		t.Errorf("without the app, the A Better Antivirus shortcut opens %q", target)
	}
	if !exists(e.reportsShortcut()) {
		t.Error("without the app, no ABA reports shortcut")
	}
}

func TestRefreshAddsTheAppShortcutOnce(t *testing.T) {
	// Listed by a version from before the app; the update brought it.
	e := testEntry(t)
	if err := e.register("v0.10.0"); err != nil {
		t.Fatal(err)
	}
	if exists(e.appShortcut()) {
		t.Fatal("an ABA shortcut before there was an app")
	}
	e.app = filepath.Join(e.dir, "aba-app.exe")
	if err := e.appShortcutOnce(); err != nil { // what InstallApp does: no app yet, nothing
		t.Fatal(err)
	}
	if exists(e.appShortcut()) {
		t.Fatal("an ABA shortcut with no app behind it")
	}
	os.WriteFile(e.app, []byte("app"), 0o644)
	if err := e.refresh("v0.11.0"); err != nil {
		t.Fatal(err)
	}
	if !exists(e.appShortcut()) {
		t.Fatal("the update didn't add the ABA shortcut")
	}
	if exists(e.shortcut()) || exists(e.reportsShortcut()) {
		t.Error("the update that brought the app left the terminal shortcuts")
	}
	// Deleted by the owner: the next update (or the app arriving again) leaves it deleted.
	os.Remove(e.appShortcut())
	if err := e.refresh("v0.11.1"); err != nil {
		t.Fatal(err)
	}
	if err := e.appShortcutOnce(); err != nil {
		t.Fatal(err)
	}
	if exists(e.appShortcut()) {
		t.Error("the ABA shortcut came back after the owner deleted it")
	}
}

func TestAppArrivingLaterTidiesTheStartMenu(t *testing.T) {
	// Updated by a version from before the app: the update listed ABA with
	// the two terminal shortcuts, then the service fetched the app
	// (update.KeepApp -> InstallApp -> appShortcutOnce).
	e := testEntry(t)
	if err := e.register("v0.10.2"); err != nil {
		t.Fatal(err)
	}
	if !exists(e.shortcut()) || !exists(e.reportsShortcut()) {
		t.Fatal("no terminal shortcuts without the app")
	}
	e.app = filepath.Join(e.dir, "aba-app.exe")
	os.WriteFile(e.app, []byte("app"), 0o644)
	if err := e.appShortcutOnce(); err != nil {
		t.Fatal(err)
	}
	if !exists(e.appShortcut()) {
		t.Fatal("no ABA shortcut once the app came")
	}
	if exists(e.shortcut()) || exists(e.reportsShortcut()) {
		t.Error("the terminal shortcuts stayed next to the app's")
	}
	// A later update, a repair: still just the one.
	if err := e.refresh("v0.11.0"); err != nil {
		t.Fatal(err)
	}
	if err := e.register("v0.11.0"); err != nil {
		t.Fatal(err)
	}
	if !exists(e.appShortcut()) || exists(e.shortcut()) || exists(e.reportsShortcut()) {
		t.Errorf("after an update and a repair: ABA %v, A Better Antivirus %v, ABA reports %v",
			exists(e.appShortcut()), exists(e.shortcut()), exists(e.reportsShortcut()))
	}
}

func TestAppShortcutOnceBeforeTheListing(t *testing.T) {
	// A first install copies the app before ABA is listed: no shortcut yet
	// (and no error); the listing right after makes it.
	e := withApp(t)
	if err := e.appShortcutOnce(); err != nil {
		t.Fatal(err)
	}
	if exists(e.appShortcut()) {
		t.Error("a shortcut made before the listing")
	}
}

func TestRemoveWebViewProfile(t *testing.T) {
	lad := t.TempDir()
	profile := filepath.Join(lad, "ABA", "webview", "EBWebView", "Default")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(profile, "Cookies"), []byte("x"), 0o644)
	removed, err := removeWebViewProfile(lad)
	if err != nil || !removed {
		t.Fatalf("removed %v, %v", removed, err)
	}
	if exists(filepath.Join(lad, "ABA")) {
		t.Error("ABA's empty folder is still there")
	}
	// Nothing there: nothing to do, no error.
	if removed, err := removeWebViewProfile(lad); removed || err != nil {
		t.Errorf("second time: %v, %v", removed, err)
	}
	if removed, err := removeWebViewProfile(filepath.Join(lad, "nobody")); removed || err != nil {
		t.Errorf("a profile that isn't there: %v, %v", removed, err)
	}
}

func TestRemoveWebViewProfileKeepsOtherFiles(t *testing.T) {
	lad := t.TempDir()
	os.MkdirAll(filepath.Join(lad, "ABA", "webview"), 0o755)
	os.WriteFile(filepath.Join(lad, "ABA", "notes.txt"), []byte("mine"), 0o644)
	if _, err := removeWebViewProfile(lad); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(lad, "ABA", "notes.txt")) {
		t.Error("deleted a file that isn't the WebView2 profile")
	}
}

// The person owns their LocalAppData: a junction planted in the profile must
// not lead an administrator's delete out of it.
func TestRemoveWebViewProfileStaysInside(t *testing.T) {
	lad := t.TempDir()
	victim := t.TempDir()
	keep := filepath.Join(victim, "important.txt")
	if err := os.WriteFile(keep, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	webview := filepath.Join(lad, "ABA", "webview")
	if err := os.MkdirAll(webview, 0o755); err != nil {
		t.Fatal(err)
	}
	// A junction inside the profile, and one as the profile itself.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(webview, "EBWebView"), victim).CombinedOutput(); err != nil {
		t.Skipf("can't make a junction here: %v %s", err, out)
	}
	removeWebViewProfile(lad)
	if !exists(keep) {
		t.Fatal("deleted a file through a junction in the profile")
	}

	lad2 := t.TempDir()
	os.MkdirAll(filepath.Join(lad2, "ABA"), 0o755)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(lad2, "ABA", "webview"), victim).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	removeWebViewProfile(lad2)
	if !exists(keep) {
		t.Fatal("deleted a file through a junction as the profile folder")
	}
}

func TestIsApp(t *testing.T) {
	dir := paths.InstallDir()
	for img, want := range map[string]bool{
		filepath.Join(dir, "aba-app.exe"):                 true,
		filepath.Join(dir, "ABA-APP.EXE"):                 true,
		filepath.Join(dir, "aba-app.exe.old-17958626938"): true, // moved aside by an update while open
		filepath.Join(dir, "aba.exe"):                     false,
		filepath.Join(dir, "updates", "aba-app.exe"):      false,
		`C:\Users\x\Downloads\aba-app.exe`:                false,
	} {
		if got := isApp(img); got != want {
			t.Errorf("isApp(%s) = %v, want %v", img, got, want)
		}
	}
}
