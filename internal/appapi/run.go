package appapi

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
)

func runCmd(cmd *exec.Cmd, stdin []byte, line func(string)) error {
	if !filepath.IsAbs(cmd.Path) {
		return &exec.Error{Name: cmd.Path, Err: os.ErrNotExist}
	}
	cmd.Dir = filepath.Dir(cmd.Path)
	if stdin != nil {
		// Through a pipe, not a file: secrets never touch the disk.
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	scanLines(out, line)
	return cmd.Wait()
}
