package notify

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/appsec"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// appAvailable reports whether the desktop app is installed and can run
// (the machine-wide WebView2 runtime it pins to is there).
func appAvailable() bool {
	if fi, err := os.Stat(paths.InstalledApp()); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	_, err := appsec.ResolveRuntime()
	return err == nil
}

// openAppFor opens the desktop app on alert a, as administrator (Windows
// asks), when the app is available. It reports whether that's taken care
// of: the app opened, or the person said no to Windows' prompt (then
// nothing else opens either). Any other failure: false, so the caller shows
// the report in the browser instead.
func openAppFor(a *alerts.Alert) (handled bool, err error) {
	if !appAvailable() {
		return false, nil
	}
	err = RunElevated(paths.InstalledApp(), "--alert", a.ID)
	if err == nil || errors.Is(err, windows.ERROR_CANCELLED) {
		return true, nil
	}
	return false, err
}

// reportButtonNote is what the popup says under its "Show full report" button.
func reportButtonNote() string {
	if appAvailable() {
		return "Opens everything ABA found in the ABA app"
	}
	return "Opens everything ABA found in your web browser"
}
