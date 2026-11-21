//go:build darwin

package main

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
)

// When a script tells Finder to copy a file ("tell application Finder to
// duplicate ..."), the process that opens the file is neither the script nor
// Finder but DesktopServicesHelper: an Apple helper that launchd starts for
// each copy, whose parent is launchd. Nothing in the file event leads back to
// whoever asked.
//
// Finder itself knows. The first time a process sends it an Apple event, it
// asks the privacy system (TCC) whether that sender may control it, and logs
// the answer with the sender's pid:
//
//	Finder: [com.apple.appleevents:main] TCC RESULT: [sess=… pid=53411 uid:501,…] ACCESS GRANTED
//
// Measured: that line is written ~25 ms before DesktopServicesHelper is
// spawned, and reaches `log stream` ~15–30 ms after it is written. So a root
// daemon that follows Finder's log knows, by the time the copy helper opens a
// bait, which processes have been driving Finder.
//
// Limits: the log is not an API and its wording can change in any update; the
// line is written once per sender *process* (Finder caches the answer), so a
// long-lived sender is remembered here for as long as it lives; and if two
// processes are driving Finder at the same time, both are suspects.

type aeSender struct {
	Facts procFacts
	Seen  time.Time
	// How long after Finder wrote the line it reached us (-1: unknown, the
	// sender was found by the fallback instead).
	LogLag time.Duration
}

type finderLog struct {
	mu      sync.Mutex
	senders map[int]aeSender
	Lines   int
	Lags    []time.Duration
}

var tccResultPid = regexp.MustCompile(`TCC RESULT: \[[^\]]*\bpid=(\d+)`)

func startFinderLog() (*finderLog, error) {
	f := &finderLog{senders: map[int]aeSender{}}
	c := exec.Command("/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate",
		`process == "Finder" AND subsystem == "com.apple.appleevents" AND eventMessage BEGINSWITH "TCC RESULT: ["`)
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			var m struct {
				EventMessage string `json:"eventMessage"`
				Timestamp    string `json:"timestamp"` // "2026-11-21 06:02:30.167123-0700"
			}
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			sm := tccResultPid.FindStringSubmatch(m.EventMessage)
			if sm == nil {
				continue
			}
			pid, _ := strconv.Atoi(sm[1])
			// Take the sender's facts now: a script host may be gone soon.
			facts := factsForPid(pid)
			now := time.Now()
			lag := time.Duration(-1)
			if t, err := time.Parse("2006-01-02 15:04:05.999999-0700", m.Timestamp); err == nil {
				lag = now.Sub(t)
			}
			f.mu.Lock()
			f.Lines++
			f.Lags = append(f.Lags, lag)
			if _, known := f.senders[pid]; !known {
				f.senders[pid] = aeSender{Facts: facts, Seen: now, LogLag: lag}
			}
			f.mu.Unlock()
		}
		c.Wait()
	}()
	return f, nil
}

// suspects returns the processes that have sent Finder Apple events: any seen
// in the last 10 s, even if they have exited since (a script host that asked
// for a small copy is usually gone by the time the copy's event arrives; its
// parent, the program that matters, is not), and older ones that are still
// running, most recent first.
func (f *finderLog) suspects() []aeSender {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []aeSender
	for pid, s := range f.senders {
		recent := time.Since(s.Seen) < 10*time.Second
		alive := syscall.Kill(pid, 0) == nil && pathOfPid(pid) == s.Facts.Path
		if !recent && !alive {
			delete(f.senders, pid) // gone, or the pid was reused
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

// Apple helpers that copy files on Finder's behalf.
func isFinderCopier(p procFacts) bool {
	return p.Platform && filepath.Base(p.Path) == "DesktopServicesHelper"
}

var sevRank = map[severity]int{sevIgnored: 0, sevInfo: 1, sevWarn: 2, sevCritical: 3}

// runningScriptHosts is the fallback when Finder's log line is late: every
// running AppleScript host. A script that asked Finder to copy is still
// waiting for Finder's answer while the copy happens.
func runningScriptHosts() []aeSender {
	out, err := exec.Command("/bin/ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil
	}
	var l []aeSender
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		if base := filepath.Base(f[len(f)-1]); base == "osascript" || base == "osacompile" {
			if facts := factsForPid(pid); facts.Platform {
				l = append(l, aeSender{Facts: facts, Seen: time.Now(), LogLag: -1})
			}
		}
	}
	return l
}
