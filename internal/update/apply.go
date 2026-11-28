package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// Dir holds downloaded updates and the rollback copy, somewhere only
// administrators and the service can write to (updatesDir, per system).
func Dir() string { return updatesDir() }

// Apply installs the verified exe at src as the CLI and the service binary,
// with the list of mining pools and the desktop app that came with it, then
// restarts the service. If the new service doesn't come up, the previous
// binaries (the app's too) are put back and restarted.
func Apply(src string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !paths.Under(src, Dir()) {
		return fmt.Errorf("refusing to install %s: updates must come from %s", src, Dir())
	}
	backup := filepath.Join(Dir(), "rollback.exe")
	if _, err := os.Stat(paths.InstalledService()); err == nil {
		if err := install.CopyFile(paths.InstalledService(), backup); err != nil {
			return fmt.Errorf("back up the current version: %w", err)
		}
	}
	// The app that came with it (Download checked it like the exe). Without
	// one, the new service fetches its own (KeepApp).
	appSrc := AppBeside(src)
	withApp := fileExists(appSrc)
	appBackup := filepath.Join(Dir(), "rollback-app.exe")
	hadApp := false
	if withApp {
		var err error
		if hadApp, err = backupApp(appBackup); err != nil {
			return fmt.Errorf("back up the current app: %w", err)
		}
	}
	swap := func(from string) error {
		for _, dst := range []string{paths.InstalledCLI(), paths.InstalledService()} {
			if err := install.CopyFile(from, dst); err != nil {
				return fmt.Errorf("%s: %w", dst, err)
			}
		}
		return nil
	}
	if err := svcctl.Stop(); err != nil {
		return fmt.Errorf("stop the service: %w", err)
	}
	if err := swap(src); err != nil {
		logf("update: install failed (%v); restoring the previous version", err)
		swap(backup)
		svcctl.Start()
		return err
	}
	// The list of mining pools that came with it (Download checked it like
	// the exe). Without one the service fetches its own (see minertrap).
	if pools := PoolsBeside(src); fileExists(pools) {
		if err := install.CopyFile(pools, minertrap.PoolsFile()); err != nil {
			logf("update: the list of mining pools wasn't installed: %v", err)
		}
	}
	// Not worth failing the update over: protection doesn't depend on it.
	if withApp {
		if err := appInstall(appSrc); err != nil {
			logf("update: the ABA app wasn't installed: %v", err)
		}
	}
	if err := svcctl.Start(); err != nil {
		logf("update: new version did not start (%v); rolling back", err)
		if e := swap(backup); e != nil {
			logf("update: rollback copy failed: %v", e)
		}
		if withApp {
			if e := restoreApp(appBackup, hadApp); e != nil {
				logf("update: putting back the previous app failed: %v", e)
			}
		}
		if e := svcctl.Start(); e != nil {
			logf("update: previous version did not start either: %v", e)
		}
		return fmt.Errorf("the new version failed to start, so the previous one was restored: %w", err)
	}
	return nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// Cleanup removes old downloads, keeping keep (the file in use, if any, with
// what came with it) and the rollback copies.
func Cleanup(keep string) {
	files, _ := filepath.Glob(filepath.Join(Dir(), "aba-*.exe*"))
	lists, _ := filepath.Glob(filepath.Join(Dir(), "aba-*.pools.txt*"))
	for _, f := range append(files, lists...) {
		if keep != "" && (paths.Same(f, keep) || paths.Same(f, PoolsBeside(keep)) || paths.Same(f, AppBeside(keep))) {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f), "rollback.exe") {
			continue
		}
		os.Remove(f)
	}
}
