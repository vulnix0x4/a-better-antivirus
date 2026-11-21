package install

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide; the install plan
// itself (install.go) is shared and calls into this.

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// CurrentUser resolves the user being protected (whoever ran the installer,
// not the administrator account it's running as) and where their folders are.
func CurrentUser() (config.UserInfo, error) {
	return config.UserInfo{}, platform.Unsupported("installing ABA")
}

// cleanupSteps run right after the first check: clearing away what earlier
// generations of ABA left behind.
func cleanupSteps() []Step { return nil }

// detectionSteps switch on whatever the operating system needs to notice a
// bait being opened, remembering how it was. restoreSteps undo that on
// uninstall.
func detectionSteps() []Step { return nil }
func restoreSteps() []Step   { return nil }

// AddToPath makes `aba` in dir something people can type in a terminal.
// RemoveFromPath undoes it.
func AddToPath(dir string) error      { return platform.Unsupported("putting aba on the PATH") }
func RemoveFromPath(dir string) error { return platform.Unsupported("putting aba on the PATH") }

// deleteProgramFiles removes the install folder on uninstall, including the
// program that's doing the uninstalling.
func deleteProgramFiles() (string, error) {
	return "", platform.Unsupported("uninstalling ABA")
}

// scheduleDelete deletes p now, or as soon as it's no longer in use.
func scheduleDelete(p string) {}
