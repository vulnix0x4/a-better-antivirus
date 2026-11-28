package appapi

import (
	"context"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/sysenv"
)

// RunCLI runs the CLI (a console program) without a console window and
// feeds line its output. Go quotes every argument (syscall.EscapeArg), and
// Command allows none that the page made up.
func RunCLI(ctx context.Context, exe string, args []string, line func(string)) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	// The machine's locations, not the person's (see package sysenv): this
	// CLI runs with the app's administrator rights.
	cmd.Env = sysenv.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return runCmd(cmd, line)
}
