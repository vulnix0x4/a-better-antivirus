//go:build !windows

package appapi

import (
	"context"
	"os/exec"
)

// RunCLI runs the CLI and feeds line its output.
func RunCLI(ctx context.Context, exe string, args []string, stdin []byte, line func(string)) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	return runCmd(cmd, stdin, line)
}
