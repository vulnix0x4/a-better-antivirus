package procinfo

// What the autopsy (package autopsy) asks about a frozen process on macOS.

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/machmem"
)

// StartedAt says when a process started.
func StartedAt(pid uint32) (time.Time, error) {
	ct, err := CreateTime(pid)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMicro(ct), nil
}

// OpenFiles lists the ordinary files a process has open (from lsof).
func OpenFiles(pid uint32) ([]string, error) {
	out, err := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", strconv.FormatUint(uint64(pid), 10), "-F", "tn").Output()
	if err != nil && len(out) == 0 {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	return parseLsofFiles(string(out)), nil
}

// parseLsofFiles reads lsof's -F output: a "t" line with the type of each
// file, then an "n" line with its name. Only ordinary files are kept.
func parseLsofFiles(s string) []string {
	var out []string
	typ := ""
	for _, l := range strings.Split(s, "\n") {
		if l == "" {
			continue
		}
		switch l[0] {
		case 'f':
			typ = ""
		case 't':
			typ = l[1:]
		case 'n':
			if typ == "REG" && strings.HasPrefix(l[1:], "/") {
				out = append(out, l[1:])
			}
		}
	}
	return out
}

// ReadMemory hands fn a process's own writable memory, a chunk at a time,
// at most limit bytes in all (see machmem). fn returns false to stop.
func ReadMemory(pid uint32, limit int64, fn func(base uint64, b []byte) bool) (int64, error) {
	return machmem.Read(pid, limit, fn)
}
