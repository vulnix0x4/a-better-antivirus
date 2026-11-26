package autopsy

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// appeared is when a file came to be where it is. A copy can keep the time
// its original was last written (cp -p); its inode change time is its own.
func appeared(fi os.FileInfo) time.Time {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		c := time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
		if m := fi.ModTime(); m.After(c) {
			return m
		}
		return c
	}
	return fi.ModTime()
}

// DefaultStagingDirs are where stealers on Linux stage what they collect.
func DefaultStagingDirs(c *Case) []Dir {
	out := []Dir{{Path: "/tmp", Depth: 3}, {Path: "/var/tmp", Depth: 2}, {Path: "/dev/shm", Depth: 2}}
	return append(out, homeDirs(c)...)
}

// StartupDirs are the folders whose programs start at every sign-in.
func StartupDirs(c *Case) []string {
	if c.User.Profile == "" {
		return []string{"/etc/xdg/autostart"}
	}
	return []string{filepath.Join(c.User.Profile, ".config", "autostart"), "/etc/xdg/autostart"}
}
