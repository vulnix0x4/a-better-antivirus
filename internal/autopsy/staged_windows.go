package autopsy

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// appeared is when a file came to be where it is. A copy keeps the time its
// original was last written, so that one won't do: Windows gives every new
// file its own creation time.
func appeared(fi os.FileInfo) time.Time {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		c := time.Unix(0, d.CreationTime.Nanoseconds())
		if m := fi.ModTime(); m.After(c) {
			return m
		}
		return c
	}
	return fi.ModTime()
}

// DefaultStagingDirs are where stealers on Windows stage what they collect.
func DefaultStagingDirs(c *Case) []Dir {
	out := []Dir{{Path: filepath.Join(c.User.LocalAppData, "Temp"), Depth: 3}, {Path: `C:\Windows\Temp`, Depth: 2}, {Path: `C:\Users\Public`, Depth: 2}, {Path: `C:\ProgramData`, Depth: 1}}
	return append(out, homeDirs(c)...)
}

// StartupDirs are the folders whose programs Windows starts at every sign-in.
func StartupDirs(c *Case) []string {
	var out []string
	if c.User.RoamingAppData != "" {
		out = append(out, filepath.Join(c.User.RoamingAppData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}
	return append(out, `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`)
}
