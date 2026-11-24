package service

// The service on Linux: run by systemd, and hearing about bait opens from the
// kernel through fanotify (package fanwatch). The kernel stops whoever opens
// a bait inside the open and names it, so the service decides right there,
// with the opener held: package detect's first case, and the only watcher
// Linux needs.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/fanwatch"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// Run runs the service: under systemd, or in the foreground when console is
// true. The CLI talks to it with signals (see svcctl.Send).
func Run(console bool) error {
	if os.Geteuid() != 0 {
		return errors.New("the service needs root: it's started by systemd, or with sudo for debugging")
	}
	if !console {
		// Under systemd a crash would otherwise leave its trace only in the
		// journal, which `aba doctor` doesn't point at.
		os.MkdirAll(paths.DataDir(), 0o711)
		if f, err := os.OpenFile(filepath.Join(paths.DataDir(), "crash.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			fmt.Fprintf(f, "--- service %s started %s (pid %d)\n", Version, time.Now().Format(time.RFC3339), os.Getpid())
			debug.SetCrashOutput(f, debug.CrashOptions{})
		}
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGINT, unix.SIGHUP, unix.SIGUSR1, unix.SIGUSR2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newServer(console)
	ctl := make(chan svcctl.Signal, 4)
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, ctl) }()
	// Tell systemd "started" only once baits are being watched, so that
	// `aba install` returns when protection is live, not before.
	go func() {
		select {
		case <-s.ready:
		case <-time.After(25 * time.Second):
		}
		sdNotify("READY=1")
	}()
	for {
		select {
		case sig := <-sigs:
			switch sig {
			case unix.SIGHUP, unix.SIGUSR1:
				what := svcctl.Reload
				if sig == unix.SIGUSR1 {
					what = svcctl.CheckNow
				}
				select {
				case ctl <- what:
				default:
				}
			case unix.SIGUSR2:
				// Right away, not when the main loop gets to it.
				go s.safe("holds", s.reconcileHolds)
				if s.net != nil {
					s.net.Kick() // a program may just have been let back on the network
				}
			default:
				sdNotify("STOPPING=1")
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return nil
			}
		case err := <-done:
			if err != nil {
				s.log.Printf("service stopped with error: %v", err)
			}
			return err // not nil: systemd restarts it
		}
	}
}

// sdNotify tells systemd about the service's state (Type=notify).
func sdNotify(state string) {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return
	}
	if name[0] == '@' {
		name = "\x00" + name[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}

// watchers is what the service keeps for noticing bait opens on Linux.
type watchers struct {
	fan       *fanwatch.Watcher
	fanErr    error
	net       *netguard.Guard  // keeps network cut-offs in force
	dirs      *fanwatch.Dirs   // the folders baits are in
	stores    *fanwatch.Stores // the folders of the real stores, for the flight recorder
	storeDirs map[string]bool

	repairMu sync.Mutex
	repairT  *time.Timer
}

func (s *server) initWatchers() {}

// prepare gets the process ready to protect, before anything else runs.
func (s *server) prepare() {
	// Whatever the service writes (its log, the alerts) is root's alone.
	unix.Umask(0o077)
	// Network cut-offs and isolation on record come back first: after a
	// reboot nothing is in place, and the service's own control group (which
	// isolation lets through) is new after every start.
	s.net = netguard.StartGuard(s.log.Printf)
	// Who owns which program is asked while an opener is held: have the
	// answers ready.
	provenance.Warm()
	w, err := fanwatch.New()
	if err != nil {
		s.fanErr = err
		s.log.Printf("watching baits: %v", err)
	} else {
		w.OnOpen, w.TimedOut, w.Logf = s.onOpen, s.timedOut, s.log.Printf
		s.fan = w
		// The marks live in this process: planting and checking baits go
		// through it (see baits.SetTripwire).
		baits.Watch, baits.Watched = w.Watch, w.Watched
		if !w.Held() {
			s.log.Printf("this kernel has no fanotify permission events: bait opens are reported after the fact, not held")
		}
	}
	if st, err := fanwatch.NewStores(); err != nil {
		s.recWhy = "the kernel wouldn't let ABA watch the folders your real data is in (" + err.Error() + ")"
		s.log.Printf("flight recorder: %v", err)
	} else {
		st.OnOpen, st.Logf = s.onStoreOpen, s.log.Printf
		st.OnLost = func(at time.Time) { s.rec.Lost(at, at, "the kernel dropped some file events (too many at once)") }
		s.stores = st
	}
	if d, err := fanwatch.NewDirs(); err != nil {
		s.log.Printf("watching bait folders: %v; a deleted bait is noticed at the next check instead", err)
	} else {
		d.OnChange, d.Logf = s.onBaitGone, s.log.Printf
		s.dirs = d
	}
	// Why a command trusted by its exact words wasn't taken as the trusted one.
	classify.StartLog = s.log.Printf
	if err := procinfo.FreezerStatus(); err != nil {
		s.log.Printf("freezer: %v; frozen programs will only be stopped (SIGSTOP), which another program of the same user can undo", err)
	}
}

// guard is what switches instant freeze's oplocks on and off on Windows. On
// Linux every bait is watched the same way whether or not openers get frozen
// on the spot (that's decided per open), and a watched file can be deleted
// like any other: nothing to do. baitsChanged keeps the marks.
func (s *server) guard(files []string) {}

// guardCounts reports how many bait files are watched right now, and how
// many should be.
func (s *server) guardCounts() (armed, want int) {
	if s.fan == nil {
		return 0, 0
	}
	return s.fan.Counts()
}

// baitsChanged is told whenever the set of bait files may have changed (and
// after every check of the baits): mark what's there now.
func (s *server) baitsChanged(st *config.State) {
	var files, all []string
	for _, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		for _, f := range bs.Files {
			all = append(all, f.Path)
			if f.Audit {
				files = append(files, f.Path)
			}
		}
	}
	if s.dirs != nil {
		s.mu.Lock()
		home := ""
		if s.cfg != nil {
			home = s.cfg.User.Profile
		}
		s.mu.Unlock()
		for _, err := range s.dirs.Sync(all, home) {
			s.log.Printf("watching bait folders: %v", err)
		}
	}
	if s.fan == nil {
		return
	}
	for _, err := range s.fan.Sync(files) {
		s.log.Printf("watching baits: %v", err)
	}
}

// onBaitGone hears from the kernel that a bait was deleted, renamed away or
// replaced, or a folder holding baits was. Whoever did it is reported the way
// a deletion is everywhere (an alert, no response: deleting isn't stealing),
// and the baits are put back at once instead of at the next check.
func (s *server) onBaitGone(c fanwatch.Change) {
	img := ""
	if c.PID != 0 {
		classify.Remember(c.PID)
		img, _ = procinfo.ImagePath(c.PID)
	}
	if img != "" && s.IsSelf(img) && procinfo.Elevated(c.PID) {
		return // `aba bait remove`, `aba uninstall`: ABA's own tooling, as root
	}
	s.log.Printf("bait %s: %s by pid %d (%s)", c.Path, c.What, c.PID, img)
	if c.PID != 0 {
		var uid, uname string
		if id, err := procinfo.UserID(c.PID); err == nil {
			uid = id
			if u, err := user.LookupId(id); err == nil {
				uname = u.Username
			}
		}
		for _, b := range c.Baits {
			a := &detect.Access{Time: c.At, Op: detect.OpDelete, Path: b, PID: c.PID, Image: img, UserID: uid, User: uname}
			select {
			case s.accesses <- a:
			default:
			}
		}
	}
	s.repairSoon()
}

// repairSoon runs a check of the baits in a moment, once for a burst of
// changes (rm -r of a folder of them).
func (s *server) repairSoon() {
	s.repairMu.Lock()
	defer s.repairMu.Unlock()
	if s.repairT != nil {
		return
	}
	s.repairT = time.AfterFunc(700*time.Millisecond, func() {
		s.repairMu.Lock()
		s.repairT = nil
		s.repairMu.Unlock()
		unix.Kill(os.Getpid(), unix.SIGUSR1) // the same as `aba doctor --fix` asking
	})
}

// saveProgress: there's no log position to keep on Linux, only the sign of
// life the dashboard looks for.
func (s *server) saveProgress() {
	config.UpdateState(func(st *config.State) error { st.Heartbeat = time.Now(); return nil })
}

// resolve: every access the watcher reports names its bait.
func (s *server) resolve(oa *detect.Access) bool { return false }

func (s *server) startWatching(ctx context.Context) {
	if s.fan != nil {
		go s.fan.Run()
		s.log.Printf("watching baits with fanotify (openers held: %v)", s.fan.Held())
	}
	if s.dirs != nil {
		go s.dirs.Run()
		s.log.Printf("watching the folders baits are in")
	}
	if s.stores != nil {
		go s.stores.Run()
	}
	go s.watchEscapes(ctx)
	s.once1.Do(func() { close(s.listening) })
}

func (s *server) stopWatching() {
	if s.fan != nil {
		s.fan.Close()
	}
	if s.net != nil {
		s.net.Close() // what's cut off stays cut off; the next start watches again
	}
	if s.dirs != nil {
		s.dirs.Close()
	}
	if s.stores != nil {
		s.stores.Close()
	}
}

// settle is how long the autopsy waits for the kernel's reports of the
// moments before the freeze: they're queued at once.
const settle = 300 * time.Millisecond

// watchStores makes the flight recorder's real stores watched: a mark on
// every folder their files are in (see fanwatch.Stores), so that a file
// replaced by a new one is still covered. A folder that appears later (a new
// browser profile) is marked at the next check, within 5 minutes; until then
// its store doesn't count as watched.
func (s *server) watchStores(stores []baits.Store) (why, gap map[string]string) {
	why, gap = map[string]string{}, map[string]string{}
	if s.stores == nil {
		return why, gap
	}
	var dirs, files []string
	for _, st := range stores {
		dirs = append(dirs, st.Dirs()...)
		for _, f := range st.Resolve() {
			if _, bait := s.eng.IsBait(f); !bait {
				files = append(files, f)
			}
		}
	}
	failed := s.stores.Sync(dirs, files)
	prev := s.storeDirs
	s.storeDirs = map[string]bool{}
	for _, st := range stores {
		for _, d := range st.Dirs() {
			if err := failed[d]; err != nil {
				if why[st.ID] == "" {
					why[st.ID] = "ABA couldn't watch " + d + " (" + err.Error() + ")"
				}
				continue
			}
			s.storeDirs[d] = true
			if prev != nil && !prev[d] && gap[st.ID] == "" {
				gap[st.ID] = "a new folder of it appeared (" + d + "), which ABA only watches from its next check"
			}
		}
	}
	return why, gap
}

// onStoreOpen gets every open of a file in a real store's folder (the
// recorder picks out which are the store's), for the flight recorder.
func (s *server) onStoreOpen(o fanwatch.StoreOpen) {
	store, ok := s.rec.Match(o.Path)
	if !ok {
		return // another file in the same folder (a browser's history, its cache index…)
	}
	op := recorder.Open{At: o.At, Path: o.Path, PID: o.PID}
	if o.PID != 0 {
		if st, err := procinfo.ReadStat(o.PID); err == nil {
			op.PPID, op.Start = st.PPID, procinfo.StartFromTicks(st.StartTime)
		}
		op.Image, _ = procinfo.ImagePath(o.PID)
	}
	s.rec.NoteStore(store.ID, op)
}

// detectionHealth reports what Linux needs for bait opens to be noticed, and
// for a freeze to hold.
func (s *server) detectionHealth(startup bool, add func(name string, ok bool, detail string)) {
	switch {
	case s.fan == nil:
		add("Watching baits", false, fmt.Sprintf("this kernel won't let ABA watch files (%v)", s.fanErr))
	case !s.fan.Held():
		add("Watching baits", true, "on; this kernel can't stop a program inside its open, so readers are frozen a moment after")
	default:
		add("Watching baits", true, "on, the kernel stops whoever opens one until ABA has looked")
	}
	if err := procinfo.FreezerStatus(); err != nil {
		add("Freezer", false, fmt.Sprintf("frozen programs are only stopped, which a program of yours could undo (%v)", err))
	} else {
		add("Freezer", true, "on, nothing running as you can thaw what ABA freezes")
	}
}

const aliasWhy = "it opened this through a second name the file was given (%s: a hard link, or the bait renamed): a trick to read a file without appearing to"

// onOpen gets every open of a bait, from the kernel. While the opener is
// held: freeze it if it deserves it, then let the open go ahead (a frozen
// process never gets to use it). What isn't frozen here is reported to the
// engine as an access, which judges it in full.
func (s *server) onOpen(ev fanwatch.Event) (deny bool) {
	// Who started it can only be seen while it's alive, and a short-lived
	// reader is gone before the engine gets to it.
	classify.Remember(ev.PID)
	if ev.Alias != "" {
		s.log.Printf("bait %s was opened under another name: %s", ev.Path, ev.Alias)
		s.eng.NoteEvasion(ev.PID, fmt.Sprintf(aliasWhy, ev.Alias))
	}
	if ev.Held && s.decideOpen(ev.Path, ev.At, ev.PID) {
		go s.safe("terminal notice", func() { tellTerminal(ev.PID) })
		return false
	}
	a := &detect.Access{Time: ev.At, Op: detect.OpRead, Path: ev.Path, Alias: ev.Alias, PID: ev.PID}
	a.Image, _ = procinfo.ImagePath(ev.PID)
	if id, err := procinfo.UserID(ev.PID); err == nil {
		a.UserID = id
		if u, err := user.LookupId(id); err == nil {
			a.User = u.Username
		}
	}
	select {
	case s.accesses <- a:
	default:
		s.log.Printf("too many bait opens at once: dropped one by pid %d (%s)", ev.PID, a.Image)
	}
	return false
}

// timedOut answers for a verdict that took too long (see fanwatch). An
// ordinary program of a user is refused the bait: it loses nothing it needs,
// and a stealer can't buy time by making itself slow to judge. Anything of
// the system's is let through.
func (s *server) timedOut(ev fanwatch.Event) (deny bool) {
	return procinfo.UserSession(ev.PID) && !procinfo.Elevated(ev.PID)
}

// watchEscapes puts a frozen process that got out of the frozen group back,
// and says so (see procinfo.Escaped).
//
// It can happen without ill will: a desktop that starts an app asks systemd
// to give the new process a group of its own, and that request can arrive
// just after ABA froze it. Put back, it stays put. A helper of a stealer
// would ask again and again, and every time the frozen program runs until
// ABA looks next. So ABA looks often while it holds anything, and a process
// that gets out a third time within a minute is ended: nothing asks three
// times by accident.
func (s *server) watchEscapes(ctx context.Context) {
	const often, idle = 20 * time.Millisecond, 500 * time.Millisecond
	seen := map[uint32][]time.Time{}
	for {
		wait := idle
		if procinfo.Held() > 0 {
			wait = often
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if procinfo.Held() == 0 {
			continue
		}
		for _, pid := range procinfo.Escaped() {
			img, _ := procinfo.ImagePath(pid)
			var recent []time.Time
			for _, t := range seen[pid] {
				if time.Since(t) < time.Minute {
					recent = append(recent, t)
				}
			}
			recent = append(recent, time.Now())
			seen[pid] = recent
			if len(recent) >= 3 {
				err := procinfo.Kill(pid)
				delete(seen, pid)
				s.log.Printf("pid %d (%s) was moved out of the frozen group a third time within a minute; ended it (%v)", pid, img, err)
				pid, img := pid, img
				go s.safe("escape alert", func() {
					s.eng.SystemAlert(alerts.KindTamper, config.TierCritical, "Ended a frozen program that something kept un-freezing",
						fmt.Sprintf("%s (pid %d), which ABA froze, was moved out of the frozen group three times within a minute by another program, and ran for a moment each time. ABA ended it. Something running as you is helping it: look at what else is frozen with `aba alerts`.", img, pid), nil)
				})
				continue
			}
			s.log.Printf("pid %d (%s) was moved out of the frozen group by something other than ABA; frozen again", pid, img)
			if len(recent) == 1 {
				pid, img := pid, img
				go s.safe("escape alert", func() {
					s.eng.SystemAlert(alerts.KindTamper, config.TierWarn, "A frozen program was briefly un-frozen",
						fmt.Sprintf("%s (pid %d), which ABA froze, was moved out of the frozen group by another program, through the system's service manager. ABA froze it again within moments. A desktop does this to a program it has just started; a stealer's helper does it on purpose, and if it happens again ABA ends the program.", img, pid), nil)
				})
			}
		}
	}
}

var ttyName = regexp.MustCompile(`^/dev/(pts/\d+|tty\d+)$`)

// tellTerminal writes a line to the terminal a just-frozen program runs in.
// A server has no desktop to show an alert on, and a command that silently
// stops in the middle of someone's terminal explains nothing. (It doesn't say
// which file: that's for `aba alerts`, as root.)
func tellTerminal(pid uint32) {
	for fd := 0; fd <= 2; fd++ {
		p, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
		if err != nil || !ttyName.MatchString(p) {
			continue
		}
		t, err := unix.Open(p, unix.O_WRONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(t, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFCHR {
			img, _ := procinfo.ImagePath(pid)
			msg := fmt.Sprintf("\r\n[A Better Antivirus] %s (pid %d) was frozen: it opened a decoy file that only a password stealer has a reason to open.\r\n"+
				"  What happened:  sudo aba alerts\r\n"+
				"  It was you:     sudo aba trust <id>     Not sure: sudo aba resume <id>     End it: sudo aba kill <id>\r\n",
				filepath.Base(img), pid)
			unix.Write(t, []byte(msg))
		}
		unix.Close(t)
		return
	}
}

// detach lets a program this service starts outlive it. systemd ends
// everything in a service's control group when the service stops, so the
// program is started as a unit of its own.
func detach(cmd *exec.Cmd) {
	for _, run := range []string{"/usr/bin/systemd-run", "/bin/systemd-run"} {
		if _, err := os.Stat(run); err == nil {
			cmd.Args = append([]string{run, "--quiet", "--collect", "--"}, cmd.Args...)
			cmd.Path = run
			return
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
