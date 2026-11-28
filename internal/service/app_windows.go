package service

import (
	"fmt"
	"os"

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
// to the app; it reads the alert itself. It reports whether the app opened
// somewhere; if not, the caller shows the popup instead.
func (s *server) openApp(a *alerts.Alert) bool {
	if err := appReady(); err != nil {
		return false
	}
	launched, err := session.LaunchApp(paths.InstalledApp(), "--alert", a.ID)
	for _, l := range launched {
		s.log.Printf("desktop app: opened for alert %s in session %d (pid %d, %s)", a.ID, l.Session, l.PID, l.Pick)
	}
	if err != nil {
		s.log.Printf("desktop app: %v", err)
	}
	return len(launched) > 0
}
