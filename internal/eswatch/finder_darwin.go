package eswatch

// When a script tells Finder to copy a file ("tell application Finder to
// duplicate …", how the Atomic stealer collects documents), the process that
// opens the file is neither the script nor Finder but DesktopServicesHelper:
// an Apple helper that launchd starts for each copy. Nothing in the file
// event leads back to whoever asked.
//
// Finder itself knows. The first time a process sends it an Apple event, it
// asks the privacy system whether that sender may control it, and logs the
// answer with the sender's PID:
//
//	Finder: [com.apple.appleevents:main] TCC RESULT: [sess=… pid=53411 uid:501,…] ACCESS GRANTED
//
// Measured on macOS 15 and 26: that line is written ~25 ms before the copy
// helper is started, and reaches `log stream` within a few ms. So by the time
// the helper opens a bait, ABA knows who has been driving Finder. Following
// it, the spike named and froze a fake stealer behind a Finder copy in 16 of
// 16 runs on a Mac and 20 of 20 on GitHub's runners.
//
// Limits: the log is not an API and its wording can change in any update; the
// line is written once per sender process (Finder remembers the answer), so a
// long-lived sender is remembered here for as long as it lives; and if two
// processes are driving Finder at once, both are suspects.

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// Sender is a process that sent Finder Apple events.
type Sender struct {
	PID, PPID uint32
	Image     string
	Seen      time.Time
}

// FinderLog follows Finder's log of Apple event senders.
type FinderLog struct {
	mu      sync.Mutex
	senders map[uint32]Sender
	cmd     *exec.Cmd
	Lines   int
}

var tccResultPid = regexp.MustCompile(`TCC RESULT: \[[^\]]*\bpid=(\d+)`)

// FollowFinder starts following Finder's log, until Close.
func FollowFinder() (*FinderLog, error) {
	f := &FinderLog{senders: map[uint32]Sender{}}
	c := exec.Command("/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate",
		`process == "Finder" AND subsystem == "com.apple.appleevents" AND eventMessage BEGINSWITH "TCC RESULT: ["`)
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	f.cmd = c
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			f.line(sc.Bytes())
		}
		c.Wait()
	}()
	return f, nil
}

func (f *FinderLog) line(b []byte) {
	var m struct {
		EventMessage string `json:"eventMessage"`
	}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	sm := tccResultPid.FindStringSubmatch(m.EventMessage)
	if sm == nil {
		return
	}
	n, _ := strconv.ParseUint(sm[1], 10, 32)
	pid := uint32(n)
	// Look at the sender now: a script host may be gone soon.
	s := Sender{PID: pid, PPID: procinfo.ParentPID(pid), Seen: time.Now()}
	s.Image, _ = procinfo.ImagePath(pid)
	f.mu.Lock()
	f.Lines++
	if _, known := f.senders[pid]; !known {
		f.senders[pid] = s
	}
	f.mu.Unlock()
}

// Close stops following the log.
func (f *FinderLog) Close() {
	if f.cmd != nil && f.cmd.Process != nil {
		f.cmd.Process.Kill()
	}
}

// Suspects returns the processes that have sent Finder Apple events: any seen
// in the last 10 seconds, even if they have exited since (a script host that
// asked for a small copy is usually gone by the time the copy's event
// arrives; its parent, the program that matters, is not), and older ones that
// are still running, most recent first.
func (f *FinderLog) Suspects() []Sender {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Sender
	for pid, s := range f.senders {
		recent := time.Since(s.Seen) < 10*time.Second
		img, _ := procinfo.ImagePath(pid)
		alive := syscall.Kill(int(pid), 0) == nil && img == s.Image
		if !recent && !alive {
			delete(f.senders, pid) // gone, or the PID was reused
			continue
		}
		out = append(out, s)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Seen.After(out[j-1].Seen); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// IsFinderCopier reports whether p is the Apple helper that copies files on
// Finder's behalf.
func IsFinderCopier(p Process) bool {
	return p.Platform && filepath.Base(p.Image) == "DesktopServicesHelper"
}

// RunningScriptHosts is the fallback when Finder's log line hasn't arrived:
// every running AppleScript host (a script that asked Finder to copy is
// still waiting for Finder's answer while the copy happens).
func RunningScriptHosts() []Sender {
	snap, err := procinfo.Snapshot()
	if err != nil {
		return nil
	}
	var out []Sender
	for pid, e := range snap {
		if e.Exe != "osascript" && e.Exe != "osacompile" {
			continue
		}
		img, _ := procinfo.ImagePath(pid)
		if strings.HasPrefix(img, "/usr/bin/") {
			out = append(out, Sender{PID: pid, PPID: e.PPID, Image: img, Seen: time.Now()})
		}
	}
	return out
}
