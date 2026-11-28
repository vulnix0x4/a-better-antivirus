package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/appsec"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

// appReady reports whether the desktop app can open: it's installed (in the
// admin-only install folder) and the machine-wide WebView2 runtime it pins
// to is there.
func appReady() error {
	fi, err := os.Stat(paths.InstalledApp())
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a file", paths.InstalledApp())
	}
	_, err = appsec.ResolveRuntime()
	return err
}

// openApp opens the desktop app on alert a on every signed-in desktop: as
// the person's administrator self (their elevated token, no prompt), or, for
// someone who isn't an administrator, as themselves (the app then shows its
// locked view: an administrator needs to decide). Only the alert's ID goes
// to the app; it reads the alert itself. It reports whether the app started
// somewhere; if not, the caller shows the popup instead.
//
// Started isn't shown: the app can still fail (its guard refusing after a
// WebView2 update, say). So for each session it started in, it's watched in
// the background (nothing here waits) until it says it showed its window;
// if it ends any other way, or an elevated one stays silent too long,
// fallback(session) shows the person the popup there instead.
func (s *server) openApp(a *alerts.Alert, fallback func(session uint32)) bool {
	if err := appReady(); err != nil {
		return false
	}
	// A marker left from opening this alert before (the autopsy opens it again).
	if old, err := filepath.Glob(filepath.Join(paths.AppDir(), "shown-*-"+a.ID)); err == nil {
		for _, f := range old {
			os.Remove(f)
		}
	}
	launched, err := session.LaunchApp(paths.InstalledApp(), "--alert", a.ID, "--from-service")
	for _, l := range launched {
		s.log.Printf("desktop app: opened for alert %s in session %d (pid %d, %s)", a.ID, l.Session, l.PID, l.Pick)
		go s.safe("desktop app watch", func() {
			defer l.Close()
			marker := paths.AppShownFile(l.Session, a.ID)
			shown := func() bool { _, err := os.Lstat(marker); return err == nil }
			ok := waitAppShown(l, shown, l.Pick.Elevated(), appShowTimeout, 500*time.Millisecond, time.Sleep)
			os.Remove(marker)
			if !ok {
				_, code := l.Exited()
				s.log.Printf("desktop app: didn't show alert %s in session %d (exit code %d): the popup instead", a.ID, l.Session, code)
				fallback(l.Session)
			}
		})
	}
	if err != nil {
		s.log.Printf("desktop app: %v", err)
	}
	return len(launched) > 0
}
