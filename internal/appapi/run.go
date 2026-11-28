package appapi

import (
	"os"
	"os/exec"
	"path/filepath"
)

func runCmd(cmd *exec.Cmd, line func(string)) error {
	if !filepath.IsAbs(cmd.Path) {
		return &exec.Error{Name: cmd.Path, Err: os.ErrNotExist}
	}
	cmd.Dir = filepath.Dir(cmd.Path)
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
