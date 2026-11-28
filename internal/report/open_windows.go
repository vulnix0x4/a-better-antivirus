package report

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/sysenv"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Where is how to get back to the reports, said at the bottom of the page
// and in the popup.
func Where() string {
	if _, err := os.Stat(paths.InstalledApp()); err == nil {
		return "Start menu > ABA" // the app, which shows every report
	}
	return "Start menu > ABA reports"
}

// Open opens url in the default browser, as the person at the screen.
//
// Run as administrator (`aba report` asks Windows for that, to read the
// report), it doesn't start the browser itself, which would then run with
// administrator rights too: it asks Explorer, which hands the address to
// the browser in your own, ordinary rights.
func Open(url string) error {
	if winsec.IsElevated() {
		// The Windows folder from the machine's settings: the environment's
		// SystemRoot is the person's to set (see package sysenv).
		explorer := filepath.Join(sysenv.Machine().Defaults().SystemRoot, "explorer.exe")
		// (Explorer's exit code says nothing about whether it worked.)
		return exec.Command(explorer, url).Start()
	}
	verb, _ := windows.UTF16PtrFromString("open")
	u, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}
