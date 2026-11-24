//go:build !windows

package cli

import "github.com/spf13/cobra"

// The window check is for the browser host policy, Windows only for now.
func windowCheckCmds() []*cobra.Command { return nil }
