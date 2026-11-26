//go:build !windows

package cli

import (
	"github.com/spf13/cobra"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// The miner trap is Windows only for now.

func minerCmds() []*cobra.Command { return nil }

func runMinerTest() error { return platform.Unsupported("the miner trap") }
