package autopsy

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// appeared is when a file came to be where it is. A copy can keep the time
// its original was last written; its birth time is its own.
func appeared(fi os.FileInfo) time.Time {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		b := time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec)
		if m := fi.ModTime(); m.After(b) {
			return m
		}
		return b
	}
	return fi.ModTime()
}

// DefaultStagingDirs are where stealers on a Mac stage what they collect:
// /tmp (Atomic and its kin make a folder there), the person's own temporary
// folder under /var/folders, and the home folders.
func DefaultStagingDirs(c *Case) []Dir {
	out := []Dir{{Path: "/private/tmp", Depth: 3}, {Path: "/private/var/tmp", Depth: 2}, {Path: "/Users/Shared", Depth: 2}}
	if u, err := user.Lookup(c.User.Name); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		ts, _ := filepath.Glob("/private/var/folders/*/*/T")
		for _, t := range ts {
			var st syscall.Stat_t
			if syscall.Stat(t, &st) == nil && int(st.Uid) == uid {
				out = append(out, Dir{Path: t, Depth: 3})
			}
		}
	}
	return append(out, homeDirs(c)...)
}
