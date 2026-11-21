//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// The events that can take a bait's contents somewhere:
//
//	open          the ordinary way
//	clone         clonefile(2): an instant copy on APFS, never opens the file.
//	              Finder "Duplicate" and `cp -c` do this.
//	copyfile      the kernel-side copyfile syscall (rare on local disks)
//	rename, link  moving the bait away or hard-linking it, to read it elsewhere
//	exchangedata  swapping its contents into another file
var detectEvents = []string{"open", "clone", "copyfile", "rename", "link", "exchangedata"}

type hit struct {
	Kind       string    `json:"event"`
	Bait       string    `json:"bait"`
	Paths      []string  `json:"paths"`
	Opener     procFacts `json:"opener"`
	OpenerUID  int       `json:"opener_uid"`
	ParentPid  int       `json:"parent_pid"`
	RespPid    int       `json:"responsible_pid"`
	RespPath   string    `json:"responsible_path"`
	Severity   severity  `json:"severity"`
	Reason     string    `json:"reason"`
	Culprit    procFacts `json:"culprit"`
	Chain      []string  `json:"chain"`
	Action     string    `json:"action"`
	Stopped    []int     `json:"stopped_pids"`
	EventTime  time.Time `json:"t_event"`    // when the kernel made the event
	RecvTime   time.Time `json:"t_received"` // when this program read it from eslogger
	JudgedTime time.Time `json:"t_judged"`
	ActedTime  time.Time `json:"t_acted"` // when the opener was stopped
	FromSelf   bool      `json:"-"`
	// Finder copies: how the asker was found, and how late Finder's log line was.
	FinderVia      string  `json:"finder_via,omitempty"`
	FinderLogLagMs float64 `json:"finder_log_lag_ms,omitempty"`
}

type watcher struct {
	baits   []string
	needles [][]byte
	action  string // stop | sigstop | kill | none
	onHit   func(h *hit)
	// Programs this watcher must never act on.
	selfPid int
	// Who has been driving Finder (nil: not followed).
	finder *finderLog
}

func newWatcher(baits []string, action string) *watcher {
	return &watcher{baits: baits, needles: needles(baits), action: action, selfPid: os.Getpid()}
}

func (w *watcher) isBait(p string) string {
	for _, b := range w.baits {
		if p == b {
			return b
		}
	}
	return ""
}

// handle looks at one raw line. Almost every line is thrown away by the byte
// search; only lines that mention a bait path are parsed.
func (w *watcher) handle(line []byte) {
	if !matchAny(line, w.needles) {
		return
	}
	recv := time.Now()
	var ev esEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return
	}
	kind := ev.kind()
	paths := pathsIn(ev.Event[kind])
	bait := ""
	for _, p := range paths {
		if b := w.isBait(p); b != "" {
			bait = b
			break
		}
	}
	if bait == "" {
		return // the bait's name only appeared inside some other string
	}
	h := &hit{Kind: kind, Bait: bait, Paths: paths, Opener: ev.Process.facts(),
		OpenerUID: ev.Process.AuditToken.EUID, ParentPid: ev.Process.PPid,
		EventTime: ev.when(), RecvTime: recv}
	if ev.Process.ResponsibleAuditToken != nil {
		h.RespPid = ev.Process.ResponsibleAuditToken.Pid
	}
	if h.Opener.Pid == w.selfPid {
		return
	}

	// 1. Instant verdict, from what the event itself says about the opener
	//    (and, for Apple tools running an errand, from the kernel's signing
	//    facts about its parents).
	v := judge(h.Opener)
	h.Severity, h.Reason, h.Culprit = v.Severity, v.Reason, v.Culprit
	for _, c := range v.Chain {
		h.Chain = append(h.Chain, fmt.Sprintf("%s[%d]", filepath.Base(c.Path), c.Pid))
	}
	// 1b. The opener is Apple's Finder copy helper: the program that matters
	//     is whoever told Finder to copy. Judge every running process that
	//     has been sending Finder Apple events; the worst verdict wins.
	var targets []int
	if isFinderCopier(h.Opener) && w.finder != nil {
		// Finder's log line is written ~25 ms before its helper opens the
		// file, but reaches us 15-30 ms after it is written: the open can win
		// the race. Give the log a moment before deciding nobody asked.
		// (Here this blocks the event loop; the real thing would not.)
		sus := w.finder.suspects()
		for wait := 0; len(sus) == 0 && wait < 10; wait++ {
			time.Sleep(10 * time.Millisecond)
			sus = w.finder.suspects()
		}
		h.FinderVia = "Finder's log"
		if len(sus) == 0 {
			sus = runningScriptHosts()
			h.FinderVia = "running AppleScript (Finder's log line had not arrived after 100 ms)"
		}
		for _, s := range sus {
			sv := judge(s.Facts)
			if sevRank[sv.Severity] > sevRank[h.Severity] || len(targets) == 0 && sevRank[sv.Severity] == sevRank[h.Severity] {
				h.Severity, h.Culprit = sv.Severity, sv.Culprit
				h.Reason = "copied by Finder on behalf of " + filepath.Base(s.Facts.Path) + ": " + sv.Reason
				h.Chain = []string{fmt.Sprintf("%s[%d]", filepath.Base(h.Opener.Path), h.Opener.Pid), "(Finder, asked by)"}
				for _, c := range sv.Chain {
					h.Chain = append(h.Chain, fmt.Sprintf("%s[%d]", filepath.Base(c.Path), c.Pid))
				}
				targets = []int{s.Facts.Pid}
				h.FinderLogLagMs = float64(s.LogLag.Microseconds()) / 1000
			}
		}
	}
	if targets == nil {
		targets = []int{h.Opener.Pid}
	}
	h.JudgedTime = time.Now()

	// 2. Stop it. The opener first (that is the one holding the data), then
	//    the program judged responsible and everything under it.
	//
	//    "stop" uses pid_suspend(2): unlike SIGSTOP, another program of the
	//    same user cannot undo it (measured: SIGCONT does nothing, pid_resume
	//    is refused). Only root can resume. "sigstop" is there to compare.
	h.Action = "none"
	if h.Severity == sevCritical && w.action != "none" {
		var stop func(pid int) bool
		switch w.action {
		case "kill":
			h.Action = "killed (SIGKILL)"
			stop = func(pid int) bool { return syscall.Kill(pid, syscall.SIGKILL) == nil }
		case "sigstop":
			h.Action = "frozen (SIGSTOP)"
			stop = func(pid int) bool { return syscall.Kill(pid, syscall.SIGSTOP) == nil }
		default:
			h.Action = "frozen (pid_suspend)"
			stop = func(pid int) bool { return pidSuspend(pid) == nil || syscall.Kill(pid, syscall.SIGSTOP) == nil }
		}
		// Never Apple's own copy helper: it serves this one copy, but it is
		// a system process and ABA does not act on those.
		for _, t := range targets {
			if t > 1 && t != w.selfPid && !isFinderCopier(factsForPid(t)) && stop(t) {
				h.Stopped = append(h.Stopped, t)
			}
		}
		h.ActedTime = time.Now()
		if c := h.Culprit.Pid; c > 1 && c != targets[0] && stop(c) {
			h.Stopped = append(h.Stopped, c)
		}
		for _, k := range descendants(h.Culprit.Pid) {
			if k != targets[0] && k != w.selfPid && stop(k) {
				h.Stopped = append(h.Stopped, k)
			}
		}
	}
	if h.RespPid > 0 {
		h.RespPath = pathOfPid(h.RespPid)
	}
	if w.onHit != nil {
		w.onHit(h)
	}
}

func (h *hit) print() {
	ms := func(a, b time.Time) string {
		if a.IsZero() || b.IsZero() {
			return "-"
		}
		return fmt.Sprintf("%.2f ms", float64(b.Sub(a).Microseconds())/1000)
	}
	fmt.Printf("\n%s  %s on %s\n", strings.ToUpper(string(h.Severity)), h.Kind, h.Bait)
	fmt.Printf("  opener       %s [pid %d, uid %d]\n", h.Opener.Path, h.Opener.Pid, h.OpenerUID)
	fmt.Printf("  signing      platform=%v team=%q id=%q flags=0x%x\n", h.Opener.Platform, h.Opener.TeamID, h.Opener.SigningID, h.Opener.CSFlags)
	fmt.Printf("  chain        %s\n", strings.Join(h.Chain, " <- "))
	fmt.Printf("  responsible  %s [pid %d]\n", h.RespPath, h.RespPid)
	fmt.Printf("  verdict      %s\n", h.Reason)
	fmt.Printf("  action       %s %v\n", h.Action, h.Stopped)
	fmt.Printf("  timing       kernel event -> received %s, -> judged %s, -> acted %s\n",
		ms(h.EventTime, h.RecvTime), ms(h.EventTime, h.JudgedTime), ms(h.EventTime, h.ActedTime))
}

// cmdWatch: watch the given baits until interrupted.
func cmdWatch(args []string) {
	fs := newFlags("watch")
	action := fs.String("action", "stop", "what to do with a critical reader: stop (pid_suspend), sigstop, kill or none")
	events := fs.String("events", strings.Join(detectEvents, ","), "eslogger events to subscribe to")
	seconds := fs.Int("seconds", 0, "stop after this many seconds (0: run until killed)")
	jsonOut := fs.String("json", "", "also append each hit as a JSON line to this file")
	var baits multiFlag
	fs.Var(&baits, "bait", "bait file (repeatable)")
	baitDir := fs.String("baitdir", "", "treat every file directly inside this folder as a bait")
	followFinder := fs.Bool("finder", true, "follow Finder's log to find who asked it to copy a bait")
	fs.Parse(args)
	if *baitDir != "" {
		ents, _ := os.ReadDir(*baitDir)
		for _, e := range ents {
			if e.Type().IsRegular() {
				baits = append(baits, filepath.Join(*baitDir, e.Name()))
			}
		}
	}
	if len(baits) == 0 {
		die("watch: give at least one -bait")
	}
	for i, b := range baits {
		if r, err := filepath.EvalSymlinks(b); err == nil {
			baits[i] = r
		}
	}
	w := newWatcher(baits, *action)
	if *followFinder {
		f, err := startFinderLog()
		if err != nil {
			die("log stream: %v", err)
		}
		w.finder = f
	}
	var jf *os.File
	if *jsonOut != "" {
		jf, _ = os.OpenFile(*jsonOut, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	}
	w.onHit = func(h *hit) {
		h.print()
		if jf != nil {
			b, _ := json.Marshal(h)
			jf.Write(append(b, '\n'))
		}
	}
	s, err := startEslogger(strings.Split(*events, ","))
	if err != nil {
		die("eslogger: %v", err)
	}
	fmt.Printf("watching %d bait(s) for %s; action on critical: %s\n", len(baits), *events, *action)
	if *seconds > 0 {
		time.AfterFunc(time.Duration(*seconds)*time.Second, s.stop)
	}
	err = s.each(w.handle)
	if w.finder != nil {
		w.finder.mu.Lock()
		var l []float64
		for _, d := range w.finder.Lags {
			if d >= 0 {
				l = append(l, float64(d.Microseconds())/1000)
			}
		}
		w.finder.mu.Unlock()
		sort.Float64s(l)
		if len(l) > 0 {
			fmt.Printf("Finder log lines: %d, reached us %.0f-%.0f ms (median %.0f) after Finder wrote them\n", len(l), l[0], l[len(l)-1], l[len(l)/2])
		}
	}
	fmt.Printf("\neslogger ended (%v) after %d events, %.1f MB\n", err, s.Lines.Load(), float64(s.Bytes.Load())/1e6)
}

// pid_suspend(2) and pid_resume(2) are private system calls (433, 434). Root
// may use them on another user's process without an entitlement (measured on
// macOS 15 and 26); a non-root caller gets EPERM even for its own processes.
func pidSuspend(pid int) error {
	if _, _, e := syscall.Syscall(433, uintptr(pid), 0, 0); e != 0 {
		return e
	}
	return nil
}

func pidResume(pid int) error {
	if _, _, e := syscall.Syscall(434, uintptr(pid), 0, 0); e != 0 {
		return e
	}
	return nil
}
