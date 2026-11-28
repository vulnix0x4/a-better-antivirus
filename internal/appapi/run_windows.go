package appapi

import (
	"context"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// RunCLI runs the CLI (a console program) without a console window and
// feeds line its output. Go quotes every argument (syscall.EscapeArg), and
// Command allows none that the page made up.
func RunCLI(ctx context.Context, exe string, args []string, stdin []byte, line func(string)) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return runCmd(cmd, stdin, line)
}
