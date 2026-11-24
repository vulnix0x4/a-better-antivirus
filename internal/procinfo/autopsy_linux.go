package procinfo

// What the autopsy (package autopsy) asks about a frozen process on Linux.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	btimeOnce sync.Once
	btime     time.Time
)

// bootTime is when the machine started (/proc/stat's btime).
func bootTime() time.Time {
	btimeOnce.Do(func() {
		b, _ := os.ReadFile("/proc/stat")
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "btime "); ok {
				n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				btime = time.Unix(n, 0)
			}
		}
	})
	return btime
}

// userHZ is the unit of /proc's clock ticks: 100 on every Linux ABA runs on.
const userHZ = 100

// StartFromTicks turns a start time in clock ticks after boot (Stat.StartTime)
// into the time of day.
func StartFromTicks(ticks uint64) time.Time {
	return bootTime().Add(time.Duration(ticks) * time.Second / userHZ)
}

// StartedAt says when a process started.
func StartedAt(pid uint32) (time.Time, error) {
	st, err := ReadStat(pid)
	if err != nil {
		return time.Time{}, err
	}
	if st.State == 'Z' || st.State == 'X' {
		return time.Time{}, fmt.Errorf("process %d has exited", pid)
	}
	return StartFromTicks(st.StartTime), nil
}

// OpenFiles lists the files a process has open (not sockets, pipes or devices).
func OpenFiles(pid uint32) ([]string, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		p, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "/dev/") {
			continue
		}
		out = append(out, strings.TrimSuffix(p, " (deleted)"))
	}
	return out, nil
}

// ReadMemory hands fn a process's own writable memory (heap, stack, the
// data it made), a chunk at a time, at most limit bytes in all. What it has
// mapped from files read-only is left out: it's on disk anyway. fn returns
// false to stop.
func ReadMemory(pid uint32, limit int64, fn func(base uint64, b []byte) bool) (int64, error) {
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, err
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return 0, err
	}
	defer mem.Close()
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	var total int64
	sc := bufio.NewScanner(bytes.NewReader(maps))
	for sc.Scan() {
		lo, hi, ok := writableRegion(sc.Text())
		if !ok {
			continue
		}
		for a := lo; a < hi; a += chunk {
			n := hi - a
			if n > chunk {
				n = chunk
			}
			if total+int64(n) > limit {
				return total, nil
			}
			k, _ := mem.ReadAt(buf[:n], int64(a))
			if k <= 0 {
				break
			}
			total += int64(k)
			if !fn(a, buf[:k]) {
				return total, nil
			}
		}
	}
	return total, nil
}

// writableRegion reads one line of /proc/<pid>/maps: a private, readable
// and writable region that isn't the kernel's.
func writableRegion(line string) (lo, hi uint64, ok bool) {
	f := strings.Fields(line)
	if len(f) < 5 || len(f[1]) < 4 || f[1][0] != 'r' || f[1][1] != 'w' || f[1][3] != 'p' {
		return 0, 0, false
	}
	if len(f) >= 6 && (f[5] == "[vvar]" || f[5] == "[vsyscall]" || f[5] == "[vdso]") {
		return 0, 0, false
	}
	a, b, found := strings.Cut(f[0], "-")
	if !found {
		return 0, 0, false
	}
	lo, err1 := strconv.ParseUint(a, 16, 64)
	hi, err2 := strconv.ParseUint(b, 16, 64)
	return lo, hi, err1 == nil && err2 == nil && hi > lo
}
