package update

import (
	"path/filepath"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// updatesDir is next to the app, not inside it: a file added to a signed
// app bundle breaks its signature. Only root can write there.
func updatesDir() string { return filepath.Join(paths.SupportDir(), "Updates") }
