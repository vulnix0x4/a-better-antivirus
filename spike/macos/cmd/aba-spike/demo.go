//go:build darwin

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// cmdDemo is the whole loop, measured: plant a bait, run the harmless fake
// stealer as the ordinary user from a Downloads-like folder, catch it, name
// it, stop it, and report how long each step took and how far it got.

type runResult struct {
	Run            int      `json:"run"`
	Caught         bool     `json:"caught"`
	OpenerPath     string   `json:"opener_path"`
	OpenerPid      int      `json:"opener_pid"`
	RightProcess   bool     `json:"named_the_right_process"`
	Severity       severity `json:"severity"`
	Reason         string   `json:"reason"`
	Frozen         bool     `json:"frozen"`
	SurvivedCont   bool     `json:"still_frozen_after_the_user_sent_sigcont"`
	ReadBait       bool     `json:"bait_was_read_before_the_freeze"`
	LootAfterBait  uint64   `json:"other_files_read_before_the_freeze"`
	OpenToEventMs  float64  `json:"open_to_kernel_event_ms"`
	OpenToRecvMs   float64  `json:"open_to_received_ms"`
	OpenToSignalMs float64  `json:"open_to_sigstop_sent_ms"`
	OpenToFrozenMs float64  `json:"open_to_last_sign_of_life_ms"`
}

func readStamp(path string) (n uint64, t time.Time) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 16 {
		return 0, time.Time{}
	}
	return binary.LittleEndian.Uint64(b[0:]), time.Unix(0, int64(binary.LittleEndian.Uint64(b[8:])))
}

func readSteps(path string) map[string]time.Time {
	out := map[string]time.Time{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m struct {
			Step string `json:"step"`
			T    int64  `json:"t_unix_nano"`
		}
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out[m.Step] = time.Unix(0, m.T)
		}
	}
	return out
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func msBetween(a, b time.Time) float64 {
	if a.IsZero() || b.IsZero() {
		return -1
	}
	return float64(b.Sub(a).Nanoseconds()) / 1e6
}

func cmdDemo(args []string) {
	fs := newFlags("demo")
	runs := fs.Int("runs", 10, "how many times to run the fake stealer")
	uid := fs.Int("uid", 501, "run the fake stealer as this user")
	gid := fs.Int("gid", 20, "and this group")
	dir := fs.String("dir", "/Users/Shared/aba-spike-demo", "scratch folder for the bait and the fake stealer")
	stealer := fs.String("stealer", "", "path to the built fake-stealer binary")
	action := fs.String("action", "stop", "stop (pid_suspend), sigstop or kill")
	how := fs.String("how", "open", "how the fake stealer reads the bait: open, mmap")
	events := fs.String("events", strings.Join(detectEvents, ","), "eslogger events")
	jsonOut := fs.String("json", "", "write results as JSON to this file")
	rate := fs.Int("rate", 0, "files per second the fake stealer reads after the bait (0: flat out)")
	before := fs.Int("before", 0, "files the fake stealer reads before the bait")
	fs.Parse(args)
	if *stealer == "" {
		die("demo: -stealer is required")
	}
	if os.Geteuid() != 0 {
		die("demo: must run as root (eslogger needs it)")
	}

	// Scratch folder that looks like a home: Documents with the bait, loot the
	// stealer moves on to, Downloads where the "downloaded" program lives.
	os.RemoveAll(*dir)
	docs := filepath.Join(*dir, "Documents")
	loot := filepath.Join(*dir, "Documents", "loot")
	dl := filepath.Join(*dir, "Downloads")
	for _, d := range []string{*dir, docs, loot, dl} {
		os.MkdirAll(d, 0o755)
	}
	bait := filepath.Join(docs, "passwords.txt")
	os.WriteFile(bait, []byte("bank: hunter2 (fake, planted by aba-spike)\n"), 0o644)
	probe := filepath.Join(*dir, "probe.txt")
	os.WriteFile(probe, []byte("probe\n"), 0o644)
	for i := 0; i < 40; i++ {
		os.WriteFile(filepath.Join(loot, fmt.Sprintf("file%02d.txt", i)), []byte(strings.Repeat("made-up loot\n", 64)), 0o644)
	}
	filepath.Walk(*dir, func(p string, _ os.FileInfo, _ error) error { return os.Chown(p, *uid, *gid) })
	defer os.RemoveAll(*dir)
	if r, err := filepath.EvalSymlinks(bait); err == nil {
		bait = r
	}
	if r, err := filepath.EvalSymlinks(probe); err == nil {
		probe = r
	}

	w := newWatcher([]string{bait, probe}, *action)
	hits := make(chan *hit, 64)
	w.onHit = func(h *hit) { hits <- h }
	s, err := startEslogger(strings.Split(*events, ","))
	if err != nil {
		die("eslogger: %v", err)
	}
	ended := make(chan error, 1)
	go func() { ended <- s.each(w.handle) }()
	defer s.stop()

	asUser := &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*gid)}}

	// Wait until eslogger is really delivering: have an ordinary process read
	// the probe file until its open shows up.
	ready := false
	t0 := time.Now()
	for !ready && time.Since(t0) < 20*time.Second {
		c := exec.Command("/bin/cat", probe)
		c.SysProcAttr = asUser
		c.Run()
		select {
		case h := <-hits:
			ready = h.Bait == probe
		case err := <-ended:
			die("eslogger stopped before delivering anything: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !ready {
		die("eslogger delivered nothing in 20 s")
	}
	fmt.Printf("eslogger delivering after %.1f s\n", time.Since(t0).Seconds())
	time.Sleep(300 * time.Millisecond)
	for len(hits) > 0 {
		<-hits
	}

	var results []runResult
	for i := 1; i <= *runs; i++ {
		exe := filepath.Join(dl, fmt.Sprintf("FreeGameInstaller-%d", i))
		if err := copyFile(*stealer, exe, 0o755); err != nil {
			die("copy stealer: %v", err)
		}
		os.Chown(exe, *uid, *gid)
		stamp := filepath.Join(*dir, fmt.Sprintf("stamp-%d", i))
		logf := filepath.Join(*dir, fmt.Sprintf("steps-%d.jsonl", i))
		c := exec.Command(exe, "-bait", bait, "-loot", loot, "-stamp", stamp, "-log", logf, "-how", *how,
			"-rate", fmt.Sprint(*rate), "-before", fmt.Sprint(*before))
		c.SysProcAttr = asUser
		if err := c.Start(); err != nil {
			die("start stealer: %v", err)
		}
		r := runResult{Run: i}
		var h *hit
	wait:
		for {
			select {
			case h = <-hits:
				if h.Bait == bait && h.Opener.Pid == c.Process.Pid {
					break wait
				}
			case <-time.After(40 * time.Second):
				h = nil
				break wait
			}
		}
		if h != nil {
			r.Caught = true
			r.OpenerPath, r.OpenerPid = h.Opener.Path, h.Opener.Pid
			r.RightProcess = h.Opener.Pid == c.Process.Pid
			r.Severity, r.Reason = h.Severity, h.Reason
			time.Sleep(150 * time.Millisecond)
			n1, _ := readStamp(stamp)
			time.Sleep(150 * time.Millisecond)
			n2, last := readStamp(stamp)
			r.Frozen = n1 == n2
			if *action == "kill" {
				r.Frozen = syscall.Kill(c.Process.Pid, 0) != nil || n1 == n2
			}
			r.LootAfterBait = n2
			if *action != "kill" {
				// An accomplice running as the same user tries to thaw it.
				kc := exec.Command("/bin/kill", "-CONT", fmt.Sprint(c.Process.Pid))
				kc.SysProcAttr = asUser
				kc.Run()
				time.Sleep(150 * time.Millisecond)
				n3, _ := readStamp(stamp)
				r.SurvivedCont = n3 == n2
			}
			steps := readSteps(logf)
			pre := steps["pre_open"]
			_, r.ReadBait = steps["read"]
			r.OpenToEventMs = msBetween(pre, h.EventTime)
			r.OpenToRecvMs = msBetween(pre, h.RecvTime)
			r.OpenToSignalMs = msBetween(pre, h.ActedTime)
			r.OpenToFrozenMs = msBetween(pre, last)
			if n2 == 0 {
				// Stopped before it finished its first loot file: the last
				// sign of life is the bait read (or the open) itself.
				lastStep := steps["opened"]
				if t, ok := steps["read"]; ok {
					lastStep = t
				}
				r.OpenToFrozenMs = msBetween(pre, lastStep)
			}
		}
		syscall.Kill(c.Process.Pid, syscall.SIGKILL)
		c.Wait()
		os.Remove(exe)
		results = append(results, r)
		fmt.Printf("run %2d: caught=%v right-process=%v %s frozen=%v | open->event %.2f ms, ->received %.2f ms, ->SIGSTOP %.2f ms | last sign of life %.2f ms after open, read bait=%v, other files read=%d\n",
			i, r.Caught, r.RightProcess, r.Severity, r.Frozen, r.OpenToEventMs, r.OpenToRecvMs, r.OpenToSignalMs, r.OpenToFrozenMs, r.ReadBait, r.LootAfterBait)
		// Let eslogger catch up before the next run, so that runs do not
		// inherit each other's backlog: read the probe file and wait for
		// that open to come out the other end.
		d0 := time.Now()
		pc := exec.Command("/bin/cat", probe)
		pc.SysProcAttr = asUser
		pc.Run()
	drain:
		for {
			select {
			case ph := <-hits:
				if ph.Bait == probe && ph.Opener.Pid == pc.Process.Pid {
					break drain
				}
			case <-time.After(60 * time.Second):
				break drain
			}
		}
		if d := time.Since(d0); d > 100*time.Millisecond {
			fmt.Printf("        (eslogger needed %.2f s to work through what this run left queued)\n", d.Seconds())
		}
		time.Sleep(200 * time.Millisecond)
	}

	summarize := func(name string, get func(runResult) float64) {
		var v []float64
		for _, r := range results {
			if r.Caught && get(r) >= 0 {
				v = append(v, get(r))
			}
		}
		if len(v) == 0 {
			return
		}
		sort.Float64s(v)
		fmt.Printf("  %-34s min %.2f  median %.2f  max %.2f ms  (n=%d)\n", name, v[0], v[len(v)/2], v[len(v)-1], len(v))
	}
	caught, right, frozen, readBait, survived := 0, 0, 0, 0, 0
	var loot0 []float64
	for _, r := range results {
		if r.Caught {
			caught++
		}
		if r.RightProcess {
			right++
		}
		if r.Frozen {
			frozen++
		}
		if r.ReadBait {
			readBait++
		}
		if r.SurvivedCont {
			survived++
		}
		loot0 = append(loot0, float64(r.LootAfterBait))
	}
	sort.Float64s(loot0)
	fmt.Printf("\n%d runs: caught %d, named the right process %d, frozen %d\n", len(results), caught, right, frozen)
	if *action != "kill" {
		fmt.Printf("  still frozen after the same user sent it SIGCONT: %d of %d\n", survived, len(results))
	}
	summarize("open -> kernel made the event", func(r runResult) float64 { return r.OpenToEventMs })
	summarize("open -> watcher received it", func(r runResult) float64 { return r.OpenToRecvMs })
	summarize("open -> SIGSTOP sent", func(r runResult) float64 { return r.OpenToSignalMs })
	summarize("open -> last sign of life", func(r runResult) float64 { return r.OpenToFrozenMs })
	if len(loot0) > 0 {
		fmt.Printf("  bait read before the freeze in %d of %d runs; other files read before the freeze: min %.0f median %.0f max %.0f\n",
			readBait, len(results), loot0[0], loot0[len(loot0)/2], loot0[len(loot0)-1])
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(*jsonOut, b, 0o644)
	}
}
