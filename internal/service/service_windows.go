package service

// The service on Windows: run by the service control manager, and hearing
// about bait opens two ways. Package instant holds an oplock on every bait, so
// Windows pauses whoever opens one and the service can freeze it right there;
// the Security event log reports every read a moment later, as the backup.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/evtlog"
	"github.com/vulnix0x4/a-better-antivirus/internal/instant"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Run runs as a Windows service, or in the foreground when console is true.
func Run(console bool) error {
	if console {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := newServer(true)
		return s.run(ctx, nil)
	}
	// A service has no console: without this, a crash (an unrecovered panic in
	// some goroutine, a fatal runtime error) leaves no trace at all.
	os.MkdirAll(paths.DataDir(), 0o755)
	if f, err := os.OpenFile(filepath.Join(paths.DataDir(), "crash.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		fmt.Fprintf(f, "--- service %s started %s (pid %d)\n", Version, time.Now().Format(time.RFC3339), os.Getpid())
		debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	return svc.Run(paths.ServiceName, &handler{})
}

type handler struct{}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptParamChange
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newServer(false)
	done := make(chan error, 1)
	ctl := make(chan svcctl.Signal, 4)
	go func() { done <- s.run(ctx, ctl) }()
	// Report "running" only once bait access is actually being watched, so
	// `aba install` returns when protection is live, not before.
	select {
	case <-s.ready:
	case err := <-done:
		if err != nil {
			s.log.Printf("service failed to start: %v", err)
			return false, 1
		}
		return false, 0
	case <-time.After(25 * time.Second):
	}
	status <- svc.Status{State: svc.Running, Accepts: accepts}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				// Whatever the service was in the middle of: never exit with holds
				// in place. A hold that's dropped, not released, kills its process.
				procinfo.DropHolds(time.Now().Add(time.Hour), func(string) bool { return false })
				return false, 0
			case svc.ParamChange, svcctl.ControlCheckNow:
				sig := svcctl.CheckNow
				if c.Cmd == svc.ParamChange {
					sig = svcctl.Reload
				}
				select {
				case ctl <- sig:
				default:
				}
			case svcctl.ControlReleased:
				// Right away, not when the main loop gets to it: someone is
				// waiting for their program to run again.
				go s.safe("holds", s.reconcileHolds)
			}
		case err := <-done:
			if err != nil {
				s.log.Printf("service stopped with error: %v", err)
				cancel()
				return false, 1 // non-zero exit -> SCM recovery restarts us
			}
			return false, 0
		}
	}
}

// watchers is what the service keeps for noticing bait opens on Windows.
type watchers struct {
	sub   *evtlog.Subscription
	watch *instant.Watcher

	baitIDs map[string]string    // file identity -> bait path (to recognise a bait under another name)
	notBait map[string]time.Time // audited paths that turned out not to be baits
	opens   map[uint32]openSeen  // what instant freeze last saw each program open
}

// openSeen is a bait the instant path saw a program open.
type openSeen struct {
	bait string
	at   time.Time
}

func (s *server) initWatchers() {
	s.baitIDs, s.notBait, s.opens = map[string]string{}, map[string]time.Time{}, map[uint32]openSeen{}
	s.watch = &instant.Watcher{Self: uint32(os.Getpid()), OnOpen: s.onOpen, OnGhost: s.onGhost, OnBlocked: s.onBlocked,
		Suspect: s.eng.SweepSuspect, Logf: s.log.Printf}
	s.admit = s.admitAudited
}

// prepare gets the process ready to protect, before anything else runs.
func (s *server) prepare() {
	// Debug: inspect and freeze any process. Backup: open a bait whatever its
	// permissions were changed to. Restore: hand planted files to their owner.
	for _, p := range []string{winsec.SeDebugPrivilege, "SeBackupPrivilege", "SeRestorePrivilege"} {
		if err := winsec.EnablePrivilege(p); err != nil {
			s.log.Printf("%s: %v", p, err)
		}
	}
	// Installs made by older versions let any program send the service
	// commands and said what it's for in its description: put that right.
	if changed, err := svcctl.Harden(); err != nil {
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) { // run in the foreground, not installed
			s.log.Printf("service permissions: %v", err)
		}
	} else if changed {
		s.log.Printf("service permissions tightened: only administrators can send it commands now")
	}
}

// guard sets which bait files are held for instant freeze (nil: let go of
// them all, e.g. while files are being removed).
func (s *server) guard(files []string) { s.watch.Sync(files) }

// guardCounts reports how many bait files are guarded right now, and how
// many should be.
func (s *server) guardCounts() (armed, want int) { return s.watch.Armed(), s.watch.Count() }

// baitsChanged is told whenever the set of bait files may have changed.
func (s *server) baitsChanged(st *config.State) { s.indexBaitFiles(st) }

// saveProgress notes how far the service has read, so a restart resumes there.
func (s *server) saveProgress() { s.saveBookmark() }

func (s *server) stopWatching() { s.watch.Stop() }

// resolve settles which bait an access without one was about (see lateAlias).
func (s *server) resolve(oa *detect.Access) bool { return s.lateAlias(oa) }

// startWatching starts listening to the Security log for bait accesses and
// hands them to the service's workers. (The oplock guards are armed by guard.)
func (s *server) startWatching(ctx context.Context) {
	events := make(chan string, 1024)
	go s.subscribeLoop(ctx, events)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case x := <-events:
				s.heard(ctx, x)
			}
		}
	}()
}

// heard takes one event from the Security log: if it's about a bait, on to
// the workers with it.
func (s *server) heard(ctx context.Context, x string) {
	ev, err := evtlog.Parse(x)
	if err != nil {
		return
	}
	oa, ok := ev.AsObjectAccess()
	if !ok {
		return
	}
	// Whether it's about a bait is decided on the main loop (see admitAudited),
	// not here: this runs alongside it, and would judge an access to a bait
	// added a moment ago against the list from before the reload.
	// (An access that neither reads nor deletes goes on too: the engine drops it.)
	a, _ := oa.Access()
	select {
	case s.accesses <- a:
	case <-ctx.Done():
	}
}

// admitAudited says whether an audited access is about a bait, and names the
// bait when the program reached it under another name. It is the service's
// admit: the main loop calls it, after any reload that came first.
func (s *server) admitAudited(a *detect.Access) bool {
	if _, isBait := s.eng.IsBait(a.Path); isBait {
		return true
	}
	bait, gone := s.baitFor(a.Path)
	switch {
	case bait != "":
		s.log.Printf("bait %s was opened under another name: %s", bait, a.Path)
		a.Alias, a.Path = a.Path, bait
	case gone && a.Op == detect.OpRead:
		a.Alias, a.Path = a.Path, "" // resolved by its worker: see lateAlias
	default:
		return false
	}
	return true
}

// indexBaitFiles notes each bait file's identity on disk, so a bait opened
// under another name (a hard link) is still recognised: see baitFor.
func (s *server) indexBaitFiles(st *config.State) {
	ids := map[string]string{}
	for _, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		for _, f := range bs.Files {
			if !f.Audit {
				continue
			}
			if id, ok := paths.FileID(f.Path); ok {
				ids[id] = f.Path
			}
		}
	}
	s.mu.Lock()
	s.baitIDs, s.notBait = ids, map[string]time.Time{}
	s.mu.Unlock()
}

// baitFor recognises a bait behind an audited path that isn't a bait's own.
//
// Windows logs the name a file was opened by. A hard link is a second name
// for the same file: anything running as you can make one to a bait, read the
// bait through it, and the event shows a path ABA has never heard of. The
// audit rule and the file are the same though, so the file's identity gives
// it away. (Hardly anything else on a PC has audit rules, so this runs rarely.)
//
// gone reports that there's no file at path (any more): see lateAlias.
func (s *server) baitFor(path string) (bait string, gone bool) {
	key := strings.ToLower(path)
	s.mu.Lock()
	if t, ok := s.notBait[key]; ok && time.Since(t) < time.Minute {
		s.mu.Unlock()
		return "", false
	}
	n := len(s.baitIDs)
	s.mu.Unlock()
	if n == 0 || len(path) < 3 {
		return "", false
	}
	id, ok := paths.FileID(path)
	if !ok {
		return "", true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if bait := s.baitIDs[id]; bait != "" {
		return bait, false
	}
	if len(s.notBait) > 4096 {
		s.notBait = map[string]time.Time{}
	}
	s.notBait[key] = time.Now()
	return "", false
}

// sawOpen notes that the instant path saw pid open a bait.
func (s *server) sawOpen(pid uint32, bait string) {
	s.mu.Lock()
	for p, o := range s.opens {
		if time.Since(o.at) > time.Minute {
			delete(s.opens, p)
		}
	}
	s.opens[pid] = openSeen{bait: bait, at: time.Now()}
	s.mu.Unlock()
}

// lateAlias handles an audit event for a file that no longer exists.
//
// The second name a stealer gives a bait (see baitFor) can be deleted again
// right after the read, before the event gets here: then there's no file left
// to identify. But the read itself went through the bait's oplock, so the
// instant path saw that same program open that bait a moment earlier. An
// audited read by it, under a name that has since vanished, is that read.
func (s *server) lateAlias(oa *detect.Access) bool {
	for i := 0; i < 8; i++ { // the instant path may be a moment behind the event
		s.mu.Lock()
		o, ok := s.opens[oa.PID]
		s.mu.Unlock()
		if ok && time.Since(o.at) < 10*time.Second {
			s.log.Printf("bait %s was read under a name that's gone again: %s", o.bait, oa.Alias)
			oa.Path = o.bait
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *server) subscribeLoop(ctx context.Context, out chan<- string) {
	for ctx.Err() == nil {
		st, _ := config.LoadState()
		bm := ""
		if st != nil {
			bm = st.Bookmark
		}
		sub, err := evtlog.Subscribe("Security", evtlog.BaitQuery, bm)
		if err != nil {
			s.log.Printf("subscribe: %v (retrying)", err)
			sleep(ctx, 5*time.Second)
			continue
		}
		s.mu.Lock()
		s.sub = sub
		s.mu.Unlock()
		s.log.Printf("watching Security log for bait access (resume=%v)", bm != "")
		s.once1.Do(func() { close(s.listening) })
		err = sub.Run(ctx, func(x string) {
			select {
			case out <- x:
			case <-ctx.Done():
			}
		})
		s.saveBookmark()
		s.mu.Lock()
		s.sub = nil
		s.mu.Unlock()
		sub.Close()
		if ctx.Err() == nil {
			s.log.Printf("subscription ended: %v (resubscribing)", err)
			sleep(ctx, 2*time.Second)
		}
	}
}

func (s *server) saveBookmark() {
	s.mu.Lock()
	sub := s.sub
	s.mu.Unlock()
	if sub == nil {
		return
	}
	bm := sub.BookmarkXML()
	config.UpdateState(func(st *config.State) error {
		if bm != "" && strings.Contains(bm, "RecordId") {
			st.Bookmark = bm
		}
		st.Heartbeat = time.Now()
		return nil
	})
}

// detectionHealth checks what Windows needs switched on for bait reads to be
// noticed at all: the system audit policy.
func (s *server) detectionHealth(startup bool, add func(name string, ok bool, detail string)) {
	if changed, err := winsec.EnsureFileSystemAudit(); err != nil {
		add("File auditing", false, err.Error())
	} else {
		add("File auditing", true, "on")
		if changed && !startup {
			s.eng.SystemAlert(alerts.KindAuditDisabled, config.TierWarn, "File auditing was switched off",
				"Something turned off Windows file auditing, which blinds ABA. It has been turned back on. Malware with admin rights does this; so do some 'optimizer' tools.", nil)
		}
	}
}

// onOpen gets the program(s) that just opened a bait, identified precisely by
// package instant. Freeze what deserves it; the alert is raised asynchronously.
func (s *server) onOpen(path string, at time.Time, pids []uint32) {
	for _, pid := range pids {
		s.sawOpen(pid, path)
		s.decideOpen(path, at, pid)
	}
}

const ghostWhy = "it opened the bait in a way that keeps Windows from pausing it, which only makes sense to slip past instant freeze"

// onGhost gets programs that opened a bait while refusing to be paused (see
// package instant). That's evasion in itself: marked, then decided like any
// opener. One that isn't frozen here (alert-only setup, a service) still gets
// an alert, even if it never goes on to read: it may only have been probing
// for which files are guarded.
func (s *server) onGhost(path string, at time.Time, pids []uint32, ahead bool) {
	for _, pid := range pids {
		s.sawOpen(pid, path)
		s.eng.NoteEvasion(pid, ghostWhy)
		if s.decideOpen(path, at, pid) {
			continue
		}
		pid := pid
		go s.safe("ghost open alert", func() {
			s.eng.HandleAccess(&detect.Access{PID: pid, Path: path, Op: detect.OpRead, Time: at})
		})
	}
}

// onBlocked: some program keeps a bait open, so it can't be guarded.
func (s *server) onBlocked(path string, pids []uint32) {
	st, _ := config.LoadState()
	var who []string
	for _, pid := range pids {
		ct, _ := procinfo.CreateTime(pid)
		frozen := false
		if st != nil {
			for _, f := range st.Frozen {
				frozen = frozen || (f.PID == pid && f.CreateTime == ct)
			}
		}
		if frozen {
			continue // something ABA froze while it had the bait open: expected
		}
		img, _ := procinfo.ImagePath(pid)
		who = append(who, fmt.Sprintf("%s (pid %d)", img, pid))
	}
	if len(who) == 0 || !s.once("blocked|"+strings.ToLower(path), time.Hour) {
		return
	}
	name := filepath.Base(path)
	if id, ok := s.eng.IsBait(path); ok && st != nil && st.Baits[id] != nil {
		name = st.Baits[id].Name
	}
	s.eng.SystemAlert(alerts.KindTamper, config.TierWarn, "A bait is being held open: "+name,
		strings.Join(who, ", ")+" keeps this bait open, so ABA can't guard it for instant freeze. Reading it is still caught through Windows' event log, a moment later. Holding a bait open like this is one way to weaken ABA.",
		[]alerts.BaitHit{{Name: name, Path: path, Access: "held open", Time: time.Now()}})
}

// detach lets a program this service starts outlive it, in the background.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
}
