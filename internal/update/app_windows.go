package update

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

func installedApp() string            { return paths.InstalledApp() }
func appIsWanted() bool               { return install.AppWanted() }
func installAppFile(src string) error { return install.InstallApp(src) }
