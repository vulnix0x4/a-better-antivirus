//go:build darwin

// aba-spike is the throwaway prototype for the macOS research spike. It is not
// the port: it exists to measure things on a real Mac. See ../../README.md.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func newFlags(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ExitOnError) }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, `usage: aba-spike <command>

  demo      plant a bait, run the fake stealer, catch and stop it, print the delays   (root + Full Disk Access)
  watch     watch bait files and stop whatever opens them                             (root + Full Disk Access)
  capture   save raw eslogger events that mention given strings                       (root + Full Disk Access)
  cpu       measure what watching every open on the Mac costs                         (root + Full Disk Access)
  storm     open files as fast as possible, to load the watcher
  sig       show the kernel's code-signing facts for a running process
  fda       report whether this process has Full Disk Access
  serve     run commands dropped into a root-only folder (how the spike daemon is driven)`)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "demo":
		cmdDemo(args)
	case "watch":
		cmdWatch(args)
	case "capture":
		cmdCapture(args)
	case "cpu":
		cmdCPU(args)
	case "storm":
		cmdStorm(args)
	case "sig":
		cmdSig(args)
	case "fda":
		cmdFDA(args)
	case "serve":
		cmdServe(args)
	default:
		die("unknown command %q", os.Args[1])
	}
}

// cmdSig prints what csops says about running processes, and optionally
// whether the file is notarized.
func cmdSig(args []string) {
	fs := newFlags("sig")
	nota := fs.Bool("notarized", false, "also ask whether the program is notarized (slow)")
	fs.Parse(args)
	for _, a := range fs.Args() {
		pid, err := strconv.Atoi(a)
		if err != nil {
			die("sig: %q is not a pid", a)
		}
		t0 := time.Now()
		s := signInfoForPid(pid)
		d := time.Since(t0)
		path := pathOfPid(pid)
		if s.Err != "" {
			fmt.Printf("%d %s: csops failed: %s\n", pid, path, s.Err)
			continue
		}
		sev, why := judgeOne(procFacts{Pid: pid, Path: path, Platform: s.Platform(), TeamID: s.TeamID, SigningID: s.SigningID, CSFlags: s.Flags})
		fmt.Printf("%d %s\n  %s\n  csops took %s; on its own this program would be: %s (%s)\n", pid, path, s, d, sev, why)
		if *nota {
			ok, took, msg := notarized(path)
			fmt.Printf("  notarized=%v (%s) %s\n", ok, took.Round(time.Millisecond), msg)
		}
	}
}

// cmdFDA: the only way to know is to try. Opening the system TCC database is
// what makes the program show up in the Full Disk Access list, too.
func cmdFDA(args []string) {
	for _, p := range []string{"/Library/Application Support/com.apple.TCC/TCC.db", "/Library/Preferences/com.apple.TimeMachine.plist"} {
		f, err := os.Open(p)
		if err == nil {
			f.Close()
		}
		fmt.Printf("uid=%d open %s: %v\n", os.Getuid(), p, err)
	}
}

// cmdCapture saves raw eslogger lines that contain any of the -match strings.
func cmdCapture(args []string) {
	fs := newFlags("capture")
	events := fs.String("events", "open", "comma-separated eslogger events")
	seconds := fs.Int("seconds", 10, "how long")
	out := fs.String("out", "", "file to write matching lines to")
	max := fs.Int("max", 5000, "stop after this many matching lines")
	var match multiFlag
	fs.Var(&match, "match", "keep lines containing this (repeatable; none: keep all)")
	fs.Parse(args)
	f := os.Stdout
	if *out != "" {
		var err error
		if f, err = os.Create(*out); err != nil {
			die("%v", err)
		}
		defer f.Close()
	}
	ns := needles(match)
	s, err := startEslogger(strings.Split(*events, ","))
	if err != nil {
		die("eslogger: %v", err)
	}
	time.AfterFunc(time.Duration(*seconds)*time.Second, s.stop)
	kept := 0
	err = s.each(func(line []byte) {
		if kept >= *max || (len(ns) > 0 && !matchAny(line, ns)) {
			return
		}
		kept++
		f.Write(line)
	})
	fmt.Fprintf(os.Stderr, "capture: %d events seen, %d kept, eslogger: %v\n", s.Lines.Load(), kept, err)
}

// cmdCPU measures the standing cost: eslogger's own CPU time and ours, for
// reading every event and searching it for bait paths.
func cmdCPU(args []string) {
	fs := newFlags("cpu")
	events := fs.String("events", strings.Join(detectEvents, ","), "comma-separated eslogger events")
	seconds := fs.Int("seconds", 30, "how long")
	label := fs.String("label", "", "what the Mac was doing, for the output")
	nbaits := fs.Int("baits", 40, "search each event for this many bait paths")
	top := fs.Int("top", 8, "show the N busiest programs (costs a JSON parse per event; 0 to measure the real filter only)")
	fs.Parse(args)
	var baits []string
	for i := 0; i < *nbaits; i++ {
		baits = append(baits, fmt.Sprintf("/Users/someone/Library/Application Support/FakeApp%02d/Local Storage/secret-%02d.db", i, i))
	}
	ns := needles(baits)
	s, err := startEslogger(strings.Split(*events, ","))
	if err != nil {
		die("eslogger: %v", err)
	}
	c0 := selfCPU()
	t0 := time.Now()
	time.AfterFunc(time.Duration(*seconds)*time.Second, s.stop)
	var first, last, seen uint64
	byProc := map[string]int{}
	key := []byte(`"global_seq_num":`)
	err = s.each(func(line []byte) {
		matchAny(line, ns)
		if i := bytes.Index(line, key); i >= 0 {
			j := i + len(key)
			var n uint64
			for j < len(line) && line[j] >= '0' && line[j] <= '9' {
				n = n*10 + uint64(line[j]-'0')
				j++
			}
			if seen == 0 {
				first = n
			}
			last = n
			seen++
		}
		if *top > 0 {
			var ev struct {
				Process struct {
					Executable struct {
						Path string `json:"path"`
					} `json:"executable"`
				} `json:"process"`
			}
			if json.Unmarshal(line, &ev) == nil {
				byProc[filepath.Base(ev.Process.Executable.Path)]++
			}
		}
	})
	wall := time.Since(t0)
	mine := selfCPU() - c0
	es := s.cpu()
	n := s.Lines.Load()
	fmt.Printf("== %s: events=%s for %.0f s\n", *label, *events, wall.Seconds())
	fmt.Printf("   events: %d (%.0f/s), %.1f MB of JSON (%.0f bytes each)\n", n, float64(n)/wall.Seconds(), float64(s.Bytes.Load())/1e6, float64(s.Bytes.Load())/float64(max(n, 1)))
	fmt.Printf("   eslogger CPU: %.2f s = %.1f%% of one core\n", es.Seconds(), 100*es.Seconds()/wall.Seconds())
	fmt.Printf("   watcher  CPU: %.2f s = %.1f%% of one core (read + search for %d bait paths%s)\n", mine.Seconds(), 100*mine.Seconds()/wall.Seconds(), *nbaits,
		map[bool]string{true: " + JSON parse of every event for the table below", false: ""}[*top > 0])
	if seen > 1 {
		fmt.Printf("   dropped by the kernel: %d of %d (gaps in global_seq_num)\n", int64(last-first+1)-int64(seen), last-first+1)
	}
	if *top > 0 {
		type kv struct {
			k string
			v int
		}
		var l []kv
		for k, v := range byProc {
			l = append(l, kv{k, v})
		}
		sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v })
		for i := 0; i < len(l) && i < *top; i++ {
			fmt.Printf("   %6d  %s\n", l[i].v, l[i].k)
		}
	}
	if err != nil {
		fmt.Printf("   eslogger: %v\n", err)
	}
}

// cmdStorm opens and reads small files in a loop: a busy Mac in a can.
func cmdStorm(args []string) {
	fs := newFlags("storm")
	dir := fs.String("dir", "", "folder to fill with files and read from")
	files := fs.Int("files", 200, "how many files")
	seconds := fs.Int("seconds", 20, "how long")
	rate := fs.Int("rate", 0, "opens per second to aim for (0: flat out)")
	fs.Parse(args)
	if *dir == "" {
		die("storm: -dir required")
	}
	os.MkdirAll(*dir, 0o755)
	var names []string
	for i := 0; i < *files; i++ {
		p := filepath.Join(*dir, fmt.Sprintf("s%04d", i))
		os.WriteFile(p, []byte("storm\n"), 0o644)
		names = append(names, p)
	}
	b := make([]byte, 64)
	end := time.Now().Add(time.Duration(*seconds) * time.Second)
	n := 0
	t0 := time.Now()
	for time.Now().Before(end) {
		fd, err := syscall.Open(names[n%len(names)], syscall.O_RDONLY, 0)
		if err == nil {
			syscall.Read(fd, b)
			syscall.Close(fd)
		}
		n++
		if *rate > 0 {
			if ahead := time.Duration(n)*time.Second/time.Duration(*rate) - time.Since(t0); ahead > 0 {
				time.Sleep(ahead)
			}
		}
	}
	fmt.Printf("storm: %d opens in %.1f s = %.0f/s\n", n, time.Since(t0).Seconds(), float64(n)/time.Since(t0).Seconds())
	os.RemoveAll(*dir)
}

// cmdServe is how the spike daemon is driven. launchd starts it (so that it,
// and not a terminal, is the program Full Disk Access is granted to). It then
// runs aba-spike commands dropped as JSON files into a folder only root can
// write, and saves their output where the developer can read it.
func cmdServe(args []string) {
	fs := newFlags("serve")
	dir := fs.String("dir", "/var/db/aba-spike", "root-only working folder")
	owner := fs.Int("owner", 501, "user who may read the output")
	fs.Parse(args)
	jobs := filepath.Join(*dir, "jobs")
	outd := filepath.Join(*dir, "out")
	os.MkdirAll(jobs, 0o700)
	os.Chmod(*dir, 0o711)
	os.Chmod(jobs, 0o700)
	os.MkdirAll(outd, 0o750)
	os.Chown(outd, *owner, 0)
	self, _ := os.Executable()
	fmt.Printf("%s serving %s as uid %d\n", time.Now().Format(time.RFC3339), jobs, os.Getuid())
	cmdFDA(nil)
	for {
		ents, _ := os.ReadDir(jobs)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			p := filepath.Join(jobs, e.Name())
			st, err := os.Lstat(p)
			if err != nil || !st.Mode().IsRegular() || st.Sys().(*syscall.Stat_t).Uid != 0 {
				os.Remove(p)
				continue
			}
			b, _ := os.ReadFile(p)
			os.Remove(p)
			var job struct {
				Args []string `json:"args"`
			}
			if json.Unmarshal(b, &job) != nil || len(job.Args) == 0 {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".json")
			go func() {
				logp := filepath.Join(outd, name+".log")
				lf, _ := os.Create(logp)
				os.Chown(logp, *owner, 0)
				c := exec.Command(self, job.Args...)
				c.Stdout, c.Stderr = lf, lf
				err := c.Run()
				fmt.Fprintf(lf, "\n[job %s finished: %v]\n", name, err)
				lf.Close()
				done := filepath.Join(outd, name+".done")
				os.WriteFile(done, []byte(fmt.Sprint(err)), 0o644)
				os.Chown(done, *owner, 0)
			}()
		}
		time.Sleep(150 * time.Millisecond)
	}
}
