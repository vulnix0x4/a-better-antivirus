package cli

import (
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// The clipboard bait is Windows only for now.

func clipGuardCmds() []*cobra.Command { return nil }

func runClipboardTest() error { return platform.Unsupported("the clipboard bait") }
