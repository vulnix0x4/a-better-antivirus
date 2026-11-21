// Package service is the always-on SYSTEM service: it subscribes to bait
// access events, runs the response engine, and keeps baits healthy.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/evtlog"
	"github.com/vulnix0x4/a-better-antivirus/internal/instant"
	"github.com/vulnix0x4/a-better-antivirus/internal/logx"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/notify"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Custom service control codes (128-255).
const (
	ControlCheckNow = 128
)

var Version = "dev"

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
	ctl := make(chan svc.Cmd, 4)
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
			case svc.ParamChange, ControlCheckNow:
				select {
				case ctl <- c.Cmd:
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

type server struct {
	log       *logx.Logger
	eng       *engine.Engine
	mu        sync.Mutex
	cfg       *config.Config
	secrets   *config.Secrets
	dial      *notify.DialCache
	cliExe    string
	selfExe   string
	sub       *evtlog.Subscription
	watch     *instant.Watcher
	listening chan struct{} // closed once the event-log subscription is live
	ready     chan struct{} // closed when the service is protecting (reported to Windows)
	once1     sync.Once
	once2     sync.Once

	baitIDs map[string]string    // file identity -> bait path (to recognise a bait under another name)
	notBait map[string]time.Time // audited paths that turned out not to be baits
	said    map[string]time.Time // warnings raised lately, so each is raised once
	opens   map[uint32]openSeen  // what instant freeze last saw each program open
	pubMu   sync.Mutex
}

// openSeen is a bait the instant path saw a program open.
type openSeen struct {
	bait string
	at   time.Time
}

func newServer(echo bool) *server {
	os.MkdirAll(paths.DataDir(), 0o755)
	exe, _ := os.Executable()
	s := &server{log: logx.New(paths.LogFile(), echo), selfExe: exe, cliExe: filepath.Join(filepath.Dir(exe), paths.CLIExe),
		listening: make(chan struct{}), ready: make(chan struct{}),
		baitIDs: map[string]string{}, notBait: map[string]time.Time{}, said: map[string]time.Time{}, opens: map[uint32]openSeen{}}
	if _, err := os.Stat(s.cliExe); err != nil {
		s.cliExe = exe // dev builds: one binary
	}
	s.eng = engine.New(s, uint32(os.Getpid()))
	s.watch = &instant.Watcher{Self: uint32(os.Getpid()), OnOpen: s.onOpen, OnGhost: s.onGhost, OnBlocked: s.onBlocked,
		Suspect: s.eng.SweepSuspect, Logf: s.log.Printf}
	config.SlowLock = func(d time.Duration, caller string) {
		s.log.Printf("state lock held %v by %s", d.Round(time.Millisecond), caller)
	}
	return s
}

func (s *server) reload() error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	sec, err := config.LoadSecrets()
	if err != nil {
		s.log.Printf("secrets: %v", err)
		sec = &config.Secrets{}
	}
	st, err := config.LoadState()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg, s.secrets = cfg, sec
	if s.dial == nil {
		s.dial = notify.NewDialCache(st.DialCache)
	}
	s.mu.Unlock()
	s.eng.Configure(cfg, st)
	var guarded []string
	if cfg.InstantFreeze {
		for _, bs := range st.Baits {
			if bs.Status == "retired" {
				continue
			}
			for _, f := range bs.Files {
				if f.Audit {
					guarded = append(guarded, f.Path)
				}
			}
		}
	}
	s.watch.Sync(guarded)
	s.indexBaitFiles(st)
	return nil
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
func (s *server) lateAlias(oa *evtlog.ObjectAccess) bool {
	for i := 0; i < 8; i++ { // the instant path may be a moment behind the event
		s.mu.Lock()
		o, ok := s.opens[oa.ProcessID]
		s.mu.Unlock()
		if ok && time.Since(o.at) < 10*time.Second {
			s.log.Printf("bait %s was read under a name that's gone again: %s", o.bait, oa.Alias)
			oa.ObjectName = o.bait
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *server) run(ctx context.Context, ctl <-chan svc.Cmd) error {
	s.log.Printf("ABA service %s starting (pid %d)", Version, os.Getpid())
	// Debug: inspect and freeze any process. Backup: open a bait whatever its
	// permissions were changed to. Restore: hand planted files to their owner.
	for _, p := range []string{winsec.SeDebugPrivilege, "SeBackupPrivilege", "SeRestorePrivilege"} {
		if err := winsec.EnablePrivilege(p); err != nil {
			s.log.Printf("%s: %v", p, err)
		}
	}
	if err := config.LockDataDir(); err != nil {
		s.log.Printf("restricting the data folder: %v", err)
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
	if err := s.reload(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	config.UpdateState(func(st *config.State) error {
		st.ServiceVersion = Version
		st.Heartbeat = time.Now()
		return nil
	})
	s.rehold()
	// Start listening for bait access BEFORE anything slow (the startup health
	// check takes seconds): otherwise reads right after a restart or reconfigure
	// were missed. The service only reports "running" once this is live.
	events := make(chan string, 1024)
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	go s.subscribeLoop(subCtx, events)
	select {
	case <-s.listening:
	case <-time.After(10 * time.Second):
		s.log.Printf("event log subscription not ready after 10 s; continuing")
	}
	s.markReady()
	s.safe("startup health check", func() { s.healthCheck(true) })

	// Per-PID workers: events from one process are handled in order (so they
	// aggregate into one alert) while different processes don't wait on each other.
	const workers = 8
	queues := make([]chan *evtlog.ObjectAccess, workers)
	for i := range queues {
		queues[i] = make(chan *evtlog.ObjectAccess, 256)
		go func(q chan *evtlog.ObjectAccess) {
			for oa := range q {
				func() {
					defer func() {
						if r := recover(); r != nil {
							s.log.Printf("PANIC handling event: %v\n%s", r, debug.Stack())
						}
					}()
					if oa.ObjectName == "" && !s.lateAlias(oa) {
						return
					}
					s.eng.HandleAccess(oa)
				}()
			}
		}(queues[i])
	}

	health := time.NewTicker(5 * time.Minute)
	beat := time.NewTicker(time.Minute)
	dialRefresh := time.NewTicker(30 * time.Minute)
	defer health.Stop()
	defer beat.Stop()
	defer dialRefresh.Stop()
	s.refreshDial(ctx)
	go s.updateLoop(ctx)

	for {
		select {
		case <-ctx.Done():
			s.saveBookmark()
			s.watch.Stop()
			// Let go of every hold properly (what's frozen stays suspended): a
			// hold that's simply dropped kills its process.
			procinfo.DropHolds(time.Now().Add(time.Hour), func(string) bool { return false })
			s.log.Printf("service stopping")
			return nil
		case x := <-events:
			ev, err := evtlog.Parse(x)
			if err != nil {
				continue
			}
			oa, ok := ev.AsObjectAccess()
			if !ok {
				continue
			}
			if _, isBait := s.eng.IsBait(oa.ObjectName); !isBait {
				bait, gone := s.baitFor(oa.ObjectName)
				switch {
				case bait != "":
					s.log.Printf("bait %s was opened under another name: %s", bait, oa.ObjectName)
					oa.Alias, oa.ObjectName = oa.ObjectName, bait
				case gone && winsec.AccessMaskIsRead(oa.AccessMask):
					oa.Alias, oa.ObjectName = oa.ObjectName, "" // resolved by its worker: see lateAlias
				default:
					continue
				}
			}
			h := fnv.New32a()
			fmt.Fprint(h, oa.ProcessID)
			queues[h.Sum32()%workers] <- oa
		case c := <-ctl:
			if c == svc.ParamChange {
				if err := s.reload(); err != nil {
					s.log.Printf("reload: %v", err)
				} else {
					s.log.Printf("configuration reloaded")
				}
			}
			s.safe("health check", func() { s.healthCheck(false) })
		case <-health.C:
			s.safe("health check", func() { s.healthCheck(false) })
			s.safe("learning check", s.learningCheck)
		case <-beat.C:
			s.saveBookmark()
			s.safe("holds", s.reconcileHolds)
			s.publish()
		case <-dialRefresh.C:
			s.refreshDial(ctx)
		}
	}
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

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
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

func (s *server) refreshDial(ctx context.Context) {
	s.mu.Lock()
	sec := s.secrets
	dial := s.dial
	s.mu.Unlock()
	if sec == nil || !sec.Phone.Enabled() || dial == nil {
		return
	}
	if st, _ := config.LoadState(); st != nil && st.Isolation != nil {
		return // DNS is blocked; keep the cache we have
	}
	dial.Refresh(ctx, notify.NewSender(sec.Phone, dial).Hosts())
	snap := dial.Snapshot()
	config.UpdateState(func(st *config.State) error { st.DialCache = snap; return nil })
}

// publish refreshes the status file anyone may read (see config.Public).
func (s *server) publish() {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cfg == nil {
		return
	}
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	st, _ := config.LoadState()
	total, open := alerts.Counts()
	if err := config.SavePublic(config.MakePublic(cfg, st, Version, total, open)); err != nil {
		s.log.Printf("status file: %v", err)
	}
}

// once reports whether the warning named key is due: true at most once per every.
func (s *server) once(key string, every time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.said[key]; ok && time.Since(t) < every {
		return false
	}
	s.said[key] = time.Now()
	return true
}

// ---- holds (see procinfo.Hold) ----

// rehold puts the processes on record as frozen back under a hold after a
// service restart (the old holds were let go when the service stopped).
func (s *server) rehold() {
	st, err := config.LoadState()
	if err != nil {
		return
	}
	for _, f := range st.Frozen {
		if procinfo.Alive(f.PID, f.CreateTime) {
			if err := procinfo.Hold(f.PID, f.CreateTime); err != nil {
				s.log.Printf("hold pid %d: %v", f.PID, err)
			}
		}
	}
}

// reconcileHolds lets go of holds on processes that are no longer on record
// as frozen: resumed or killed by you through the CLI, or gone.
func (s *server) reconcileHolds() {
	if procinfo.Held() == 0 {
		return
	}
	asOf := time.Now()
	st, err := config.LoadState()
	if err != nil {
		return
	}
	keep := map[string]bool{}
	for _, f := range st.Frozen {
		keep[procinfo.HoldName(f.PID, f.CreateTime)] = true
	}
	before := procinfo.Held()
	procinfo.DropHolds(asOf, func(name string) bool { return keep[name] })
	if n := before - procinfo.Held(); n > 0 {
		s.log.Printf("let go of %d hold(s) no longer on record", n)
	}
}

// ---- engine.Ops ----

func (s *server) ImagePath(pid uint32) (string, error)     { return procinfo.ImagePath(pid) }
func (s *server) CreateTime(pid uint32) int64              { t, _ := procinfo.CreateTime(pid); return t }
func (s *server) Verify(p string) authenticode.Result      { return authenticode.Verify(p) }
func (s *server) SuspendTree(pid uint32) ([]uint32, error) { return procinfo.SuspendTree(pid) }
func (s *server) KillTree(pid uint32) error                { return procinfo.KillTree(pid) }
func (s *server) Forensics(pid uint32, p *alerts.Process)  { engine.ProcessDetails(pid, p) }
func (s *server) CommandLine(pid uint32) string            { c, _ := procinfo.CommandLine(pid); return c }
func (s *server) InjectedCode(pid uint32) (string, bool)   { return procinfo.InjectedCode(pid) }
func (s *server) BlockProgram(path string) error           { return netguard.BlockProgram(path) }
func (s *server) Isolate() error                           { return netguard.Isolate(s.selfExe) }
func (s *server) DisableAdapters() ([]string, error)       { return netguard.DisableAdapters() }
func (s *server) Ancestors(pid uint32) []procinfo.Ancestor { return procinfo.Ancestors(pid, 6) }
func (s *server) RunningImage(path string) []uint32        { return procinfo.RunningImage(path) }
func (s *server) UpdateState(fn func(*config.State) error) error {
	return config.UpdateState(fn)
}
func (s *server) Logf(f string, a ...any) { s.log.Printf(f, a...) }

func (s *server) SaveAlert(a *alerts.Alert) error {
	err := alerts.Save(a)
	go s.publish()
	return err
}

func (s *server) SideLoaded(pid uint32, image string) (string, bool) {
	return procinfo.SideLoaded(pid, image, func(p string) bool { return authenticode.Verify(p).Valid })
}

func (s *server) Hold(pids []uint32) {
	for _, p := range pids {
		ct, err := procinfo.CreateTime(p)
		if err != nil {
			continue
		}
		if err := procinfo.Hold(p, ct); err != nil {
			// The plain suspension still stands; it just isn't tamper-proof.
			s.log.Printf("hold pid %d: %v", p, err)
		}
	}
}

func (s *server) SuspendMore(root uint32, already []uint32) []uint32 {
	skip := map[uint32]bool{}
	for _, p := range already {
		skip[p] = true
	}
	return procinfo.SuspendTreeExcept(root, skip, func(pid uint32) bool {
		img, err := procinfo.ImagePath(pid)
		return err == nil && !s.IsSelf(img) && !s.Elevated(pid)
	})
}

func (s *server) Resume(pids []uint32) {
	for _, p := range pids {
		procinfo.Resume(p)
	}
}

func (s *server) NotifyDesktop(a *alerts.Alert) {
	// The alert goes to the popup over a pipe: alert files are admin-only now.
	b, err := json.Marshal(notify.Envelope{Alert: a})
	if err != nil {
		s.log.Printf("desktop notify: %v", err)
		return
	}
	n, err := session.LaunchWithInput(s.cliExe, b, "notify")
	if err != nil {
		s.log.Printf("desktop notify: %v", err)
	} else if n == 0 {
		s.log.Printf("desktop notify: nobody logged in; alert %s kept in history", a.ID)
	}
}

func (s *server) NotifyPhone(a *alerts.Alert) {
	s.mu.Lock()
	sec, dial := s.secrets, s.dial
	s.mu.Unlock()
	if sec == nil || !sec.Phone.Enabled() {
		return
	}
	msg := notify.FromAlert(a)
	go func() {
		snd := notify.NewSender(sec.Phone, dial)
		var err error
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = snd.Send(ctx, msg)
			cancel()
			if err == nil {
				s.log.Printf("phone alert sent for %s", a.ID)
				return
			}
			time.Sleep(time.Duration(2<<i) * time.Second)
		}
		s.log.Printf("phone alert failed for %s: %v", a.ID, err)
	}()
}

func (s *server) PendingTest() *engine.TestRequest {
	b, err := os.ReadFile(paths.TestFile())
	if err != nil {
		return nil
	}
	var tr engine.TestRequest
	if json.Unmarshal(b, &tr) != nil || time.Since(tr.Since) > 2*time.Minute {
		return nil
	}
	return &tr
}

func (s *server) ClearTest() { os.Remove(paths.TestFile()) }

// retireLimit: more than one decoy "turning out to be installed" within a day
// isn't someone setting up their PC, it's something clearing ABA's baits out
// of its way (running the genuine apps is enough to make that happen).
const retireLimit = 24 * time.Hour

// mayRetire reports whether a decoy may be retired now, given how many were
// retired within retireLimit already; if not, it says so loudly.
func (s *server) mayRetire(recent int, id, name string) bool {
	if recent == 0 {
		return true
	}
	if s.once("retire|"+id, retireLimit) {
		s.eng.SystemAlert(alerts.KindTamper, config.TierCritical, "Kept a decoy that something tried to get retired: "+name,
			"A second app in one day looks installed, which would make ABA remove its fake "+name+" data. That's how you'd clear baits out of the way before stealing, so ABA kept this one. If you really installed it, remove the decoy yourself with `aba configure`.", nil)
	}
	return false
}

func (s *server) RetireDecoy(id, why string) {
	st, err := config.LoadState()
	if err != nil {
		return
	}
	if bs := st.Baits[id]; bs == nil || !s.mayRetire(baits.RecentlyRetired(st, retireLimit), id, bs.Name) {
		return
	}
	s.watch.Sync(nil) // let go of every bait while files are removed; reload re-arms the rest
	err = config.UpdateState(func(st *config.State) error {
		s.mu.Lock()
		u := s.cfg.User
		s.mu.Unlock()
		baits.Retire(st, u, id, why)
		return nil
	})
	if err != nil {
		s.log.Printf("retire %s: %v", id, err)
	}
	s.reload()
}

// UserSession reports whether pid is an ordinary user's program rather than
// part of Windows' services. Normally that's "not in session 0". But a
// scheduled task can run a program as you in session 0 too, without admin
// rights, and that must not make a stealer count as a service: there, it's
// the account that tells.
func (s *server) UserSession(pid uint32) bool {
	var sid uint32
	if err := windows.ProcessIdToSessionId(pid, &sid); err != nil {
		return false
	}
	if sid != 0 {
		return true
	}
	u, err := procinfo.UserSID(pid)
	return err == nil && !engine.ServiceAccount(u)
}

// onOpen gets the program(s) that just opened a bait, identified precisely by
// package instant. Freeze what deserves it; the alert is raised asynchronously.
func (s *server) onOpen(path string, at time.Time, pids []uint32) {
	for _, pid := range pids {
		s.sawOpen(pid, path)
		s.decideOpen(path, at, pid)
	}
}

func (s *server) decideOpen(path string, at time.Time, pid uint32) bool {
	ok, why := s.eng.DecideInstantWhy(pid, path)
	if !ok {
		s.log.Printf("instant: pid %d let through: %s", pid, why)
		return false
	}
	frozen, err := procinfo.SuspendTree(pid)
	if err != nil && len(frozen) == 0 {
		s.eng.Unclaim(pid)
		s.log.Printf("instant freeze of pid %d failed: %v", pid, err)
		return false
	}
	img, _ := procinfo.ImagePath(pid)
	s.log.Printf("instant freeze: %s (pid %d) opened %s; frozen %d ms after the open", img, pid, path, time.Since(at).Milliseconds())
	go s.safe("instant-freeze alert", func() { s.eng.HandleOpen(pid, path, at, frozen) })
	return true
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
			s.eng.HandleAccess(&evtlog.ObjectAccess{ProcessID: pid, ObjectName: path, AccessMask: 1, Time: at})
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

var (
	selfHashOnce sync.Once
	selfHash     string
	hashCacheMu  sync.Mutex
	hashCache    = map[string]string{}
)

// IsSelf reports whether image is a copy of ABA's own executable, by SHA-256.
// (A path check isn't enough: the CLI may run from Downloads or a build folder.)
func (s *server) IsSelf(image string) bool {
	selfHashOnce.Do(func() { selfHash, _ = procinfo.FileSHA256(s.selfExe) })
	if selfHash == "" || image == "" {
		return false
	}
	return s.Hash(image) == selfHash
}

// Hash returns a file's SHA-256, cached by path, size and modification time.
func (s *server) Hash(image string) string {
	if image == "" {
		return ""
	}
	key := strings.ToLower(image)
	if fi, err := os.Stat(image); err == nil {
		key += fmt.Sprintf("|%d|%d", fi.Size(), fi.ModTime().UnixNano())
	}
	if id, ok := paths.FileID(image); ok {
		key += "|" + id
	}
	hashCacheMu.Lock()
	h, ok := hashCache[key]
	hashCacheMu.Unlock()
	if !ok {
		h, _ = procinfo.FileSHA256(image)
		hashCacheMu.Lock()
		hashCache[key] = h
		hashCacheMu.Unlock()
	}
	return h
}

// Elevated reports whether pid runs at high (admin) or system integrity, the
// same line UAC draws. (TokenIsElevated isn't enough: restricted tokens made
// from an admin, e.g. by `runas /trustlevel`, can still claim to be elevated.)
func (s *server) Elevated(pid uint32) bool {
	lvl, err := procinfo.IntegrityLevel(pid)
	if err != nil {
		return true // can't inspect it: don't instant-freeze
	}
	return lvl >= procinfo.IntegrityHigh
}

func (s *server) markReady() { s.once2.Do(func() { close(s.ready) }) }

// safe runs fn and, if it panics, logs the panic with its stack instead of
// crashing the service (which would drop the alert or response in progress).
func (s *server) safe(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Printf("PANIC in %s: %v\n%s", name, r, debug.Stack())
		}
	}()
	fn()
}
