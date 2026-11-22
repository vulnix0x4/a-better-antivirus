package service

// The service on macOS: run by launchd, and hearing about bait opens from
// Apple's Endpoint Security through eslogger (package eswatch). eslogger
// reports an open just after it happened, so every one is package detect's
// second case: an access after the fact, which the engine judges and, if it
// deserves it, freezes.
//
// The program that opens a bait is often not the one behind it, so before an
// access is handed on, two things are put right:
//
//   - A copy Finder makes for a script is opened by Finder's helper, not by
//     the script. Finder's log says who has been driving it (see eswatch),
//     and the access goes to that program instead, with the helper as its
//     helper: frozen with it if it's judged a stealer, so the copy stops.
//   - A short-lived reader (cat, a shell running one line) is often gone by
//     the time eslogger's report arrives, and so the engine couldn't freeze
//     what started it. Then the access goes to the nearest program in its
//     chain that's still running: that's what the stealer is.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/eswatch"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// Run runs the service: under launchd, or in the foreground when console is
// true. The CLI talks to it with signals (see svcctl.Send).
func Run(console bool) error {
	if os.Geteuid() != 0 {
		return errors.New("the service needs root: it's started by launchd, or with sudo for debugging")
	}
	os.MkdirAll(paths.DataDir(), 0o711)
	if !console {
		// Under launchd a crash would otherwise leave no trace at all.
		if f, err := os.OpenFile(filepath.Join(paths.DataDir(), "crash.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
			fmt.Fprintf(f, "--- service %s started %s (pid %d)\n", Version, time.Now().Format(time.RFC3339), os.Getpid())
			debug.SetCrashOutput(f, debug.CrashOptions{})
		}
	}
	os.Remove(svcctl.ReadyFile())
	os.Remove(svcctl.WatchingFile())
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGINT, unix.SIGHUP, unix.SIGUSR1, unix.SIGUSR2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newServer(console)
	ctl := make(chan svcctl.Signal, 4)
	done := make(chan error, 1)
	go func() { done <- s.run(ctx, ctl) }()
	// Say "started" (for svcctl.Start, and so `aba install`) once baits are
	// being watched, or once it's clear they can't be yet (no Full Disk
	// Access: the install then asks for it).
	go func() {
		select {
		case <-s.ready:
		case <-time.After(25 * time.Second):
		}
		os.WriteFile(svcctl.ReadyFile(), []byte(strconv.Itoa(os.Getpid())), 0o644)
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
				go s.safe("holds", s.reconcileHolds)
			default:
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				os.Remove(svcctl.ReadyFile())
				os.Remove(svcctl.WatchingFile())
				return nil
			}
		case err := <-done:
			if err != nil {
				s.log.Printf("service stopped with error: %v", err)
			}
			os.Remove(svcctl.ReadyFile())
			os.Remove(svcctl.WatchingFile())
			return err // not nil: launchd starts it again
		}
	}
}

// watchers is what the service keeps for noticing bait opens on macOS.
type watchers struct {
	es     *eswatch.Watcher
	finder *eswatch.FinderLog
	users  sync.Map // uid -> name
}

func (s *server) initWatchers() {}

// prepare gets the process ready to protect, before anything else runs.
func (s *server) prepare() {
	// Whatever the service writes (its log, the alerts) is root's alone.
	unix.Umask(0o077)
	w := eswatch.New()
	w.OnEvent, w.OnExec, w.Logf = s.onEvent, s.onExec, s.log.Printf
	s.es = w
	if f, err := eswatch.FollowFinder(); err != nil {
		s.log.Printf("following Finder's log: %v; copies Finder makes for a script are put down to Finder's helper", err)
	} else {
		s.finder = f
	}
}

// guard: eslogger reports every open, so there's nothing to switch on or off
// per bait. baitsChanged keeps the list.
func (s *server) guard(files []string) {}

func (s *server) guardCounts() (armed, want int) {
	if s.es == nil {
		return 0, 0
	}
	return s.es.Counts()
}

// baitsChanged is told whenever the set of bait files may have changed.
func (s *server) baitsChanged(st *config.State) {
	if s.es == nil {
		return
	}
	var files []string
	for _, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		for _, f := range bs.Files {
			if f.Audit {
				files = append(files, f.Path)
			}
		}
	}
	s.es.Sync(files)
}

// saveProgress: there's no log position to keep, only the sign of life the
// dashboard looks for.
func (s *server) saveProgress() {
	config.UpdateState(func(st *config.State) error { st.Heartbeat = time.Now(); return nil })
}

// resolve: every access the watcher reports names its bait.
func (s *server) resolve(oa *detect.Access) bool { return false }

func (s *server) startWatching(ctx context.Context) {
	// Isolation is put in place by the service each time it starts: pf's
	// rules don't outlive a restart of the Mac by themselves.
	if st, _ := config.LoadState(); st != nil && st.Isolation != nil {
		if err := netguard.Isolate(s.selfExe); err != nil {
			s.log.Printf("putting the isolation back in place: %v", err)
		} else {
			s.log.Printf("the Mac is isolated (since %s): put back in place", st.Isolation.Since.Format(time.RFC3339))
		}
	}
	go s.es.Run()
	go func() {
		was, told := false, false
		var blind time.Time
		for i := 0; ; i++ {
			running, since, err := s.es.Status()
			now := running && time.Since(since) > time.Second
			if now != was {
				if now {
					s.log.Printf("watching baits with eslogger")
					os.WriteFile(svcctl.WatchingFile(), []byte(strconv.Itoa(os.Getpid())), 0o644)
					s.once1.Do(func() { close(s.listening) })
				} else {
					os.Remove(svcctl.WatchingFile())
				}
				was = now
			}
			if errors.Is(err, eswatch.ErrNoAccess) {
				if i%100 == 20 {
					s.log.Printf("waiting for Full Disk Access (System Settings > Privacy & Security > Full Disk Access: %s)", paths.ServiceDisplayName)
				}
				if blind.IsZero() {
					blind = time.Now()
				}
				// Two minutes without it: say so, once, on the desktop and the
				// phone. Without Full Disk Access ABA sees nothing at all.
				if !told && time.Since(blind) > 2*time.Minute {
					told = true
					go s.safe("access alert", func() {
						s.eng.SystemAlert(alerts.KindAuditDisabled, config.TierCritical, "ABA can't see the baits: Full Disk Access is off",
							"macOS isn't letting ABA watch files, so nothing that opens a bait is noticed. It happens after an update while ABA isn't signed by a registered developer yet (macOS takes the new version for another program), or when the switch was turned off. Open System Settings > Privacy & Security > Full Disk Access and switch on \""+paths.ServiceDisplayName+"\" (if it's on already, switch it off and on again). `sudo aba doctor --fix` opens the page.", nil)
					})
				}
			} else if now {
				blind, told = time.Time{}, false
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
}

func (s *server) stopWatching() {
	if s.es != nil {
		s.es.Close()
	}
	if s.finder != nil {
		s.finder.Close()
	}
}

// detectionHealth reports what macOS needs for bait opens to be noticed.
func (s *server) detectionHealth(startup bool, add func(name string, ok bool, detail string)) {
	running, since, err := s.es.Status()
	switch {
	case running && time.Since(since) > time.Second:
		add("Watching baits", true, "on, through Apple's eslogger: whoever opens a bait is frozen a moment later")
	case errors.Is(err, eswatch.ErrNoAccess) || !eswatch.HasFullDiskAccess():
		s.es.Retry()
		add("Watching baits", false, "macOS hasn't given ABA Full Disk Access: switch on \""+paths.ServiceDisplayName+"\" in System Settings > Privacy & Security > Full Disk Access")
	case err != nil:
		add("Watching baits", false, "eslogger isn't running: "+err.Error())
	default:
		add("Watching baits", false, "eslogger is starting")
	}
	if s.finder == nil {
		add("Finder copies", false, "Finder's log can't be followed, so a copy Finder makes for a script is put down to Finder")
	}
}

func (s *server) userName(uid uint32) string {
	if v, ok := s.users.Load(uid); ok {
		return v.(string)
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	s.users.Store(uid, name)
	return name
}

// remember keeps what the kernel said about a process, for when it's gone.
func remember(p eswatch.Process, x *eswatch.Exec) {
	r := procinfo.RecentProcess{PID: p.PID, PPID: p.PPID, Image: p.Image, Platform: p.Platform,
		TeamID: p.TeamID, SignID: p.SigningID, CSFlags: p.CSFlags}
	if x != nil {
		r.Args, r.Cwd, r.Stdin = x.Args, x.Cwd, x.Stdin
	}
	procinfo.Remember(r)
	provenance.Note(p.Image, p.CSFlags, p.Platform)
}

// onExec gets every program started.
func (s *server) onExec(x eswatch.Exec) { remember(x.Proc, &x) }

const aliasWhy = "it gave this file a second name (%s, a hard link): a trick to read a file without appearing to"

// onEvent gets every touch of a bait, from eslogger, a few milliseconds
// after it happened.
func (s *server) onEvent(ev eswatch.Event) {
	remember(ev.Proc, nil)
	pid, image, uid := ev.Proc.PID, ev.Proc.Image, ev.Proc.UID
	if ev.Op == eswatch.Link {
		s.log.Printf("bait %s was given another name: %s", ev.Path, ev.Alias)
		s.es.AddAlias(ev.Alias, ev.Path)
		s.eng.NoteEvasion(pid, fmt.Sprintf(aliasWhy, ev.Alias))
	}
	var helpers []uint32
	if eswatch.IsFinderCopier(ev.Proc) {
		if p, img, why := s.finderSender(); p != 0 {
			s.log.Printf("bait %s was copied by Finder's helper (pid %d) for %s (pid %d), %s", ev.Path, pid, img, p, why)
			// The helper is frozen with the program that asked for the copy,
			// if that one is judged a stealer: then the copy stops where it
			// is. Copies you make yourself are never touched.
			helpers = []uint32{pid}
			pid, image = p, img
		}
	} else if !procinfo.Alive(pid, 0) {
		if p, img := liveAncestor(pid); p != 0 {
			s.log.Printf("bait %s was opened by %s (pid %d), which had already exited; put down to %s (pid %d), which started it", ev.Path, image, pid, img, p)
			pid, image = p, img
		}
	}
	// Who started it is worked out now, while as much of the chain as
	// possible is still running.
	go s.safe("origin", func() { classify.Remember(pid) })
	op := detect.OpRead
	if ev.Op == eswatch.Delete {
		op = detect.OpDelete
	}
	a := &detect.Access{Time: ev.At, Op: op, Path: ev.Path, Alias: ev.Alias, PID: pid, Image: image, Helpers: helpers}
	if ev.Op == eswatch.Link {
		a.Alias = ev.Alias
	}
	if u, err := procinfo.UserID(pid); err == nil {
		a.UserID = u
		if n, err := strconv.ParseUint(u, 10, 32); err == nil {
			a.User = s.userName(uint32(n))
		}
	} else {
		a.UserID = strconv.FormatUint(uint64(uid), 10)
		a.User = s.userName(uid)
	}
	select {
	case s.accesses <- a:
	default:
		s.log.Printf("too many bait opens at once: dropped one by pid %d (%s)", pid, image)
	}
}

// finderSender is who asked Finder for the copy its helper is making: the
// program behind the most recent process that sent Finder Apple events (the
// nearest one up its chain that isn't Apple's, if it's still running).
func (s *server) finderSender() (pid uint32, image, how string) {
	var senders []eswatch.Sender
	how = "according to Finder's log"
	if s.finder != nil {
		for i := 0; i < 10 && len(senders) == 0; i++ {
			if senders = s.finder.Suspects(); len(senders) == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	if len(senders) == 0 {
		senders, how = eswatch.RunningScriptHosts(), "the only AppleScript running"
		if len(senders) != 1 {
			return 0, "", ""
		}
	}
	snd := senders[0]
	// Up from the sender (osascript, usually) to the program in its own
	// right: that's what the stealer is.
	cur, img := snd.PID, snd.Image
	for depth := 0; depth < 8; depth++ {
		parent := procinfo.ParentPID(cur)
		if cur == snd.PID && snd.PPID != 0 {
			parent = snd.PPID
		}
		if !classify.ScriptHost(filepath.Base(img)) || parent <= 1 {
			break
		}
		pimg, err := procinfo.ImagePath(parent)
		if err != nil || pimg == "" {
			break
		}
		cur, img = parent, pimg
	}
	if !procinfo.Alive(cur, 0) {
		return snd.PID, snd.Image, how
	}
	return cur, img, how
}

// liveAncestor is the nearest process up pid's chain that is still running,
// other than launchd (0 if there's none).
func liveAncestor(pid uint32) (uint32, string) {
	cur := pid
	for depth := 0; depth < 8; depth++ {
		parent := procinfo.ParentPID(cur)
		if parent <= 1 {
			return 0, ""
		}
		if procinfo.Alive(parent, 0) {
			img, err := procinfo.ImagePath(parent)
			if err != nil {
				return 0, ""
			}
			return parent, img
		}
		cur = parent
	}
	return 0, ""
}

// detach lets a program this service starts outlive it: launchd ends the
// whole process group of a daemon that stops.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
