package report

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Where is how to get back to the reports, said at the bottom of the page
// and in the popup.
const Where = "Start menu > ABA reports"

// Open opens url in the default browser, as the person at the screen.
//
// Run as administrator (`aba report` asks Windows for that, to read the
// report), it doesn't start the browser itself, which would then run with
// administrator rights too: it asks Explorer, which hands the address to
// the browser in your own, ordinary rights.
func Open(url string) error {
	if winsec.IsElevated() {
		explorer := filepath.Join(os.Getenv("SystemRoot"), "explorer.exe")
		if os.Getenv("SystemRoot") == "" {
			explorer = `C:\Windows\explorer.exe`
		}
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
