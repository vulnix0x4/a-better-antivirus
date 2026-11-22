// Package service is the always-on SYSTEM service: it hears about bait
// accesses, runs the response engine, and keeps baits healthy.
//
// This file, health.go and updater.go are the same on every operating system:
// loading the configuration, running the engine and giving it its Ops, the
// health check, phone alerts, updates. service_<os>.go has what isn't: how the
// program runs as a service there, and how it notices a bait being opened
// (which it reports through s.accesses, or s.decideOpen while the opener is
// held: see package detect).
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/logx"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/notify"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

var Version = "dev"

type server struct {
	log       *logx.Logger
	eng       *engine.Engine
	mu        sync.Mutex
	cfg       *config.Config
	secrets   *config.Secrets
	dial      *notify.DialCache
	cliExe    string
	selfExe   string
	accesses  chan *detect.Access // bait accesses the watchers report after the fact (see package detect)
	listening chan struct{}       // closed once bait accesses are being heard (on Windows, the event-log subscription is live)
	ready     chan struct{}       // closed when the service is protecting (reported to the operating system)
	once1     sync.Once
	once2     sync.Once

	// admit (optional) says whether an access from s.accesses is about a bait,
	// for a watcher that hears about other files too. The main loop calls it,
	// so it runs after any reload that came first: an access to a bait added a
	// moment ago waits for the reload that makes it known, instead of being
	// judged against the old list and dropped.
	admit func(*detect.Access) bool

	said  map[string]time.Time // warnings raised lately, so each is raised once
	pubMu sync.Mutex

	watchers // this operating system's way of noticing bait opens: service_<os>.go
}

func newServer(echo bool) *server {
	os.MkdirAll(paths.DataDir(), 0o755)
	exe, _ := os.Executable()
	s := &server{log: logx.New(paths.LogFile(), echo), selfExe: exe, cliExe: filepath.Join(filepath.Dir(exe), paths.CLIExe),
		accesses: make(chan *detect.Access, 1024), listening: make(chan struct{}), ready: make(chan struct{}),
		said: map[string]time.Time{}}
	if _, err := os.Stat(s.cliExe); err != nil {
		s.cliExe = exe // dev builds: one binary
	}
	s.eng = engine.New(s, uint32(os.Getpid()))
	s.initWatchers()
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
	s.guard(guarded)
	s.clipboardBait(cfg.ClipboardBait)
	s.baitsChanged(st)
	return nil
}

// run is the service itself, until ctx is done. ctl carries what the CLI
// tells it (see svcctl.Signal); nil when run in the foreground.
func (s *server) run(ctx context.Context, ctl <-chan svcctl.Signal) error {
	s.log.Printf("ABA service %s starting (pid %d)", Version, os.Getpid())
	s.prepare()
	if err := config.LockDataDir(); err != nil {
		s.log.Printf("restricting the data folder: %v", err)
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
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	s.startWatching(subCtx)
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
	queues := make([]chan *detect.Access, workers)
	for i := range queues {
		queues[i] = make(chan *detect.Access, 256)
		go func(q chan *detect.Access) {
			for oa := range q {
				func() {
					defer func() {
						if r := recover(); r != nil {
							s.log.Printf("PANIC handling event: %v\n%s", r, debug.Stack())
						}
					}()
					if oa.Path == "" && !s.resolve(oa) {
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
			s.saveProgress()
			s.stopWatching()
			s.clipboardBait(false) // the guards put the clipboard back as they go
			// Let go of every hold properly (what's frozen stays suspended): a
			// hold that's simply dropped kills its process.
			procinfo.DropHolds(time.Now().Add(time.Hour), func(string) bool { return false })
			s.log.Printf("service stopping")
			return nil
		case oa := <-s.accesses:
			if s.admit != nil && !s.admit(oa) {
				continue
			}
			h := fnv.New32a()
			fmt.Fprint(h, oa.PID)
			queues[h.Sum32()%workers] <- oa
		case c := <-ctl:
			// `aba clipboard test` asks for a bait now, the same way.
			if tr := s.PendingTest(); tr != nil && tr.Clipboard {
				s.safe("clipboard test", s.clipboardBaitNow)
			}
			if c == svcctl.Reload {
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
			s.saveProgress()
			s.safe("holds", s.reconcileHolds)
			s.safe("clipboard bait", func() { // people log on and off
				s.mu.Lock()
				on := s.cfg != nil && s.cfg.ClipboardBait
				s.mu.Unlock()
				s.clipboardBait(on)
			})
			s.publish()
		case <-dialRefresh.C:
			s.refreshDial(ctx)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
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
func (s *server) UserSession(pid uint32) bool              { return procinfo.UserSession(pid) }
func (s *server) Elevated(pid uint32) bool                 { return procinfo.Elevated(pid) }
func (s *server) CreateTime(pid uint32) int64              { t, _ := procinfo.CreateTime(pid); return t }
func (s *server) Verify(p string) provenance.Result        { return provenance.Verify(p) }
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
	return procinfo.SideLoaded(pid, image, func(p string) bool { return provenance.Verify(p).Valid })
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
	s.guard(nil) // let go of every bait while files are removed; reload re-arms the rest
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

// decideOpen is for a watcher that has pid held inside its open of the bait
// at path (or has just identified it there): freeze it if it deserves it. It
// reports whether it did; the alert is then raised asynchronously.
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
