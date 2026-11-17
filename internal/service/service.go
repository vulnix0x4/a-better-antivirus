// Package service is the always-on SYSTEM service: it subscribes to bait
// access events, runs the response engine, and keeps baits healthy.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/evtlog"
	"github.com/vulnix0x4/a-better-antivirus/internal/logx"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/notify"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
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
				return false, 0
			case svc.ParamChange, ControlCheckNow:
				select {
				case ctl <- c.Cmd:
				default:
				}
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
	log     *logx.Logger
	eng     *engine.Engine
	mu      sync.Mutex
	cfg     *config.Config
	secrets *config.Secrets
	dial    *notify.DialCache
	cliExe  string
	selfExe string
	sub     *evtlog.Subscription
}

func newServer(echo bool) *server {
	os.MkdirAll(paths.DataDir(), 0o755)
	exe, _ := os.Executable()
	s := &server{log: logx.New(paths.LogFile(), echo), selfExe: exe, cliExe: filepath.Join(filepath.Dir(exe), paths.CLIExe)}
	if _, err := os.Stat(s.cliExe); err != nil {
		s.cliExe = exe // dev builds: one binary
	}
	s.eng = engine.New(s, uint32(os.Getpid()))
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
	return nil
}

func (s *server) run(ctx context.Context, ctl <-chan svc.Cmd) error {
	s.log.Printf("ABA service %s starting (pid %d)", Version, os.Getpid())
	if err := winsec.EnablePrivilege(winsec.SeDebugPrivilege); err != nil {
		s.log.Printf("SeDebugPrivilege: %v", err)
	}
	if err := s.reload(); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	config.UpdateState(func(st *config.State) error {
		st.ServiceVersion = Version
		st.Heartbeat = time.Now()
		return nil
	})
	s.healthCheck(true)

	events := make(chan string, 1024)
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	go s.subscribeLoop(subCtx, events)

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
							s.log.Printf("panic handling event: %v", r)
						}
					}()
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

	for {
		select {
		case <-ctx.Done():
			s.saveBookmark()
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
				continue
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
			s.healthCheck(false)
		case <-health.C:
			s.healthCheck(false)
		case <-beat.C:
			s.saveBookmark()
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

// ---- engine.Ops ----

func (s *server) ImagePath(pid uint32) (string, error)     { return procinfo.ImagePath(pid) }
func (s *server) CreateTime(pid uint32) int64              { t, _ := procinfo.CreateTime(pid); return t }
func (s *server) Verify(p string) authenticode.Result      { return authenticode.Verify(p) }
func (s *server) SuspendTree(pid uint32) ([]uint32, error) { return procinfo.SuspendTree(pid) }
func (s *server) KillTree(pid uint32) error                { return procinfo.KillTree(pid) }
func (s *server) Forensics(pid uint32, p *alerts.Process)  { engine.ProcessDetails(pid, p) }
func (s *server) BlockProgram(path string) error           { return netguard.BlockProgram(path) }
func (s *server) Isolate() error                           { return netguard.Isolate(s.selfExe) }
func (s *server) DisableAdapters() ([]string, error)       { return netguard.DisableAdapters() }
func (s *server) SaveAlert(a *alerts.Alert) error          { return alerts.Save(a) }
func (s *server) UpdateState(fn func(*config.State) error) error {
	return config.UpdateState(fn)
}
func (s *server) Logf(f string, a ...any) { s.log.Printf(f, a...) }

func (s *server) Resume(pids []uint32) {
	for _, p := range pids {
		procinfo.Resume(p)
	}
}

func (s *server) NotifyDesktop(a *alerts.Alert) {
	n, err := session.LaunchInActiveSessions(s.cliExe, "notify", a.ID)
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

func (s *server) RetireDecoy(id, why string) {
	err := config.UpdateState(func(st *config.State) error {
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
