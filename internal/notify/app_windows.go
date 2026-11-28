package notify

import (
	"os"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/appsec"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// openAppFor opens the desktop app on alert a, as administrator (Windows
// asks), when the app is installed and can run (the machine-wide WebView2
// runtime is there). opened says whether it tried; err whether that failed.
func openAppFor(a *alerts.Alert) (opened bool, err error) {
	if fi, err := os.Stat(paths.InstalledApp()); err != nil || !fi.Mode().IsRegular() {
		return false, nil
	}
	if _, err := appsec.ResolveRuntime(); err != nil {
		return false, nil
	}
	return true, RunElevated(paths.InstalledApp(), "--alert", a.ID)
}
