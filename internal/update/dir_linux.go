package update

import (
	"path/filepath"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// updatesDir is in the program's own folder, which only administrators can
// write to.
func updatesDir() string { return filepath.Join(paths.InstallDir(), "updates") }
