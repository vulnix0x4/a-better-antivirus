package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeApp switches the desktop app on (whatever this system is) and installs
// it into a folder of the test's own.
func fakeApp(t *testing.T, wanted bool) (target string, installs *int) {
	t.Helper()
	oldHas, oldTarget, oldWanted, oldInstall := hasApp, appTarget, appWanted, appInstall
	t.Cleanup(func() { hasApp, appTarget, appWanted, appInstall = oldHas, oldTarget, oldWanted, oldInstall })
	target = filepath.Join(t.TempDir(), "aba-app.exe")
	n := 0
	hasApp = true
	appTarget = func() string { return target }
	appWanted = func() bool { return wanted }
	appInstall = func(src string) error {
		n++
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o755)
	}
	return target, &n
}

func TestAppAssetName(t *testing.T) {
	fakeApp(t, true)
	if got := AppAssetName("v1.2.3"); !strings.HasPrefix(got, "aba-app_v1.2.3_") || !strings.HasSuffix(got, ".exe") {
		t.Errorf("AppAssetName = %q", got)
	}
	hasApp = false
	if got := AppAssetName("v1.2.3"); got != "" {
		t.Errorf("no app here, but AppAssetName = %q", got)
	}
	if got := AppBeside(`C:\x\aba-v1.2.3.exe`); got != `C:\x\aba-v1.2.3.app.exe` {
		t.Errorf("AppBeside = %q", got)
	}
}

func TestDownloadBringsTheApp(t *testing.T) {
	fakeApp(t, true)
	_, rel := fakeReleases(t, map[string][]byte{AssetName("v9.9.9"): []byte("new program"), AppAssetName("v9.9.9"): []byte("new app")}, "")
	dir := t.TempDir()
	// A leftover from an earlier download of the same version mustn't count.
	os.WriteFile(AppBeside(filepath.Join(dir, "aba-v9.9.9.exe")), []byte("stale"), 0o644)
	out, err := Download(context.Background(), rel, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(AppBeside(out)); err != nil || string(b) != "new app" {
		t.Errorf("the app beside the exe: %q %v", b, err)
	}
}

func TestDownloadRefusesATamperedApp(t *testing.T) {
	fakeApp(t, true)
	app := AppAssetName("v9.9.9")
	_, rel := fakeReleases(t, map[string][]byte{AssetName("v9.9.9"): []byte("new program"), app: []byte("new app")}, app)
	dir := t.TempDir()
	if _, err := Download(context.Background(), rel, dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("an app that isn't the signed one was taken: %v", err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
		t.Errorf("left behind: %v", files)
	}
}

func TestDownloadLeavesOutAnAppNotWanted(t *testing.T) {
	fakeApp(t, false)
	_, rel := fakeReleases(t, map[string][]byte{AssetName("v9.9.9"): []byte("new program"), AppAssetName("v9.9.9"): []byte("new app")}, "")
	out, err := Download(context.Background(), rel, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(AppBeside(out)); err == nil {
		t.Error("downloaded the app for a PC that left it out")
	}
}

func TestDownloadFromAReleaseWithoutTheApp(t *testing.T) {
	// Releases from before the app.
	fakeApp(t, true)
	_, rel := fakeReleases(t, map[string][]byte{AssetName("v9.9.9"): []byte("new program")}, "")
	out, err := Download(context.Background(), rel, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(AppBeside(out)); err == nil {
		t.Error("an app out of nowhere")
	}
}

func TestEnsureAppInstallsAMissingApp(t *testing.T) {
	target, installs := fakeApp(t, true)
	_, _ = fakeReleases(t, map[string][]byte{AssetName("v9.9.9"): []byte("program"), AppAssetName("v9.9.9"): []byte("the app")}, "")
	dir := t.TempDir()
	got, err := ensureApp(context.Background(), "v9.9.9", dir)
	if err != nil || !got {
		t.Fatalf("ensureApp: %v %v", got, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "the app" {
		t.Errorf("installed %q", b)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
		t.Errorf("the download was left behind: %v", files)
	}
	// There now: nothing more to do, nothing fetched.
	if got, err := ensureApp(context.Background(), "v9.9.9", dir); got || err != nil || *installs != 1 {
		t.Errorf("second time: %v %v, %d installs", got, err, *installs)
	}
}

func TestEnsureAppLeavesItOut(t *testing.T) {
	target, _ := fakeApp(t, false)
	fakeReleases(t, map[string][]byte{AppAssetName("v9.9.9"): []byte("the app")}, "")
	if got, err := ensureApp(context.Background(), "v9.9.9", t.TempDir()); got || err != nil {
		t.Errorf("left out on purpose, but: %v %v", got, err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("installed an app this PC left out")
	}
}

func TestEnsureAppOnlyForPublishedVersions(t *testing.T) {
	target, _ := fakeApp(t, true)
	fakeReleases(t, map[string][]byte{AppAssetName("v9.9.9"): []byte("the app")}, "")
	if got, err := ensureApp(context.Background(), "ci-abc", t.TempDir()); got || err != nil {
		t.Errorf("a dev build: %v %v", got, err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("installed an app for a build that was never published")
	}
}

func TestEnsureAppRefusesATamperedApp(t *testing.T) {
	target, _ := fakeApp(t, true)
	app := AppAssetName("v9.9.9")
	fakeReleases(t, map[string][]byte{app: []byte("the app")}, app)
	if got, err := ensureApp(context.Background(), "v9.9.9", t.TempDir()); got || err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("took an app that isn't the signed one: %v %v", got, err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("installed it anyway")
	}
}

func TestEnsureAppWhenTheReleaseHasNone(t *testing.T) {
	fakeApp(t, true)
	fakeReleases(t, map[string][]byte{AssetName("v9.9.9"): []byte("program")}, "")
	if _, err := ensureApp(context.Background(), "v9.9.9", t.TempDir()); !errors.Is(err, errNoApp) {
		t.Errorf("err = %v, want errNoApp (so KeepApp stops asking)", err)
	}
}

func TestRollbackPutsTheAppBack(t *testing.T) {
	target, _ := fakeApp(t, true)
	backup := filepath.Join(t.TempDir(), "rollback-app.exe")

	// There was one: the update's is replaced by it.
	os.WriteFile(target, []byte("old app"), 0o755)
	had, err := backupApp(backup)
	if err != nil || !had {
		t.Fatalf("backupApp: %v %v", had, err)
	}
	os.WriteFile(target, []byte("new app"), 0o755)
	if err := restoreApp(backup, had); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "old app" {
		t.Errorf("after the rollback: %q", b)
	}

	// There was none: the update's is taken away again.
	os.Remove(target)
	had, err = backupApp(backup)
	if err != nil || had {
		t.Fatalf("backupApp with no app: %v %v", had, err)
	}
	if _, err := os.Stat(backup); err == nil {
		t.Error("an old backup is still there to be restored")
	}
	os.WriteFile(target, []byte("new app"), 0o755)
	if err := restoreApp(backup, had); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the rollback kept the app the failed update brought")
	}
	if left, _ := filepath.Glob(target + "*"); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}
