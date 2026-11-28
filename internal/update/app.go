package update

// The desktop app (aba-app.exe, Windows only) is a release file of its own,
// listed in the same signed SHA256SUMS.txt as aba.exe. An update brings the
// new app with the new aba.exe (Download, Apply); a PC that has none, because
// a version from before the app updated it, or it was set up from a bare
// aba.exe, gets its version's from the release (KeepApp, run by the service).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/install"
)

// hasApp: only Windows has the desktop app (tests switch it on elsewhere).
var hasApp = runtime.GOOS == "windows"

// Where the app goes, whether this PC wants it, and how it's put in place
// (app_<os>.go; tests point them at a folder of their own).
var (
	appTarget  = installedApp
	appWanted  = appIsWanted
	appInstall = installAppFile
)

// errNoApp: the release has no app for this PC. Asking again won't change that.
var errNoApp = errors.New("the release has no app for this PC")

// KeepApp installs the desktop app of version (the running service's own
// release) when this PC should have it and doesn't: a little after the
// service starts, then hourly until it's there. One that keeps failing
// (each try downloads 14 MB) is tried less and less often, down to once a
// day. It returns when ctx ends or the release has no app.
func KeepApp(ctx context.Context, version string, logf func(string, ...any)) {
	wait := 2 * time.Minute
	failed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		installed, err := ensureApp(ctx, version, Dir())
		if err != nil {
			failed++
		} else {
			failed = 0
		}
		wait = keepAppWait(failed)
		switch {
		case errors.Is(err, errNoApp):
			return
		case err != nil:
			logf("app: fetching the ABA app of %s: %v (next try in %v)", version, err, wait)
		case installed:
			logf("app: installed the ABA app of %s (signature and checksum verified)", version)
		}
	}
}

// keepAppWait is how long KeepApp waits after failed tries in a row: an
// hour, doubling with each failure, at most a day.
func keepAppWait(failed int) time.Duration {
	w := time.Hour
	for i := 1; i < failed && w < 24*time.Hour; i++ {
		w *= 2
	}
	return min(w, 24*time.Hour)
}

// ensureApp fetches and installs version's app, checked against the
// release's signed checksum list, if this PC should have it and doesn't. It
// reports whether it installed it.
func ensureApp(ctx context.Context, version, dir string) (bool, error) {
	name := AppAssetName(version)
	if name == "" || !Updatable(version) || !appWanted() || fileExists(appTarget()) {
		return false, nil
	}
	r, sums, err := published(ctx, version)
	if err != nil {
		return false, err
	}
	if _, err := lookup(sums, name); err != nil {
		return false, errNoApp
	}
	body, err := fetchListed(ctx, r, sums, name, maxExe)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	tmp := AppBeside(filepath.Join(dir, "aba-"+version+".exe"))
	if err := writeFile(tmp, body, 0o755); err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	if err := appInstall(tmp); err != nil {
		return false, err
	}
	return true, nil
}

// backupApp keeps a copy of the installed app at backup, for a rollback. It
// reports whether there was one.
func backupApp(backup string) (bool, error) {
	os.Remove(backup)
	if !fileExists(appTarget()) {
		return false, nil
	}
	return true, install.CopyFile(appTarget(), backup)
}

// restoreApp puts back the app that was there before an update (had), or
// takes away the one the update added.
func restoreApp(backup string, had bool) error {
	if had {
		return install.CopyFile(backup, appTarget())
	}
	target := appTarget()
	if !fileExists(target) {
		return nil
	}
	// Moved aside first: it may be open (CopyFile deletes such copies later).
	old := fmt.Sprintf("%s.old-%d", target, time.Now().UnixNano())
	if err := os.Rename(target, old); err != nil {
		return err
	}
	install.ScheduleDelete(old) // now, or at the next restart if it's open
	return nil
}
