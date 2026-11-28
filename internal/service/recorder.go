package service

// The flight recorder in the service: which real stores there are, keeping
// them watched (through the operating system's way of doing it, in
// service_<os>.go: watchStores), and the autopsy that reads it after a catch.
//
// The recorder never raises an alert. What it notes stays in memory and is
// only read by the autopsy of a program ABA has already caught.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netrec"
	"github.com/vulnix0x4/a-better-antivirus/internal/notify"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

// recorderState is what the service keeps about the recorder.
type recorderState struct {
	rec    *recorder.Recorder
	recMu  sync.Mutex // one sync at a time
	synced time.Time  // when the stores were last found fully watched
	// recWhy says why the recorder can't watch anything at all ("" if it
	// can): this system's watcher couldn't start.
	recWhy string

	// The network record: what programs sent, for the autopsy (see
	// package netrec). It runs while the flight recorder is on.
	netRec    *netrec.Record
	netMu     sync.Mutex
	netCancel context.CancelFunc
}

// netOn starts the network record, if it isn't running.
func (s *server) netOn() {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if s.netCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.netCancel = func() { cancel(); <-done }
	go func() {
		defer close(done)
		for {
			err := netrec.Watch(ctx, s.netRec, s.log.Printf)
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, platform.ErrUnsupported) {
				return
			}
			s.log.Printf("network record: %v; trying again in a minute", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Minute):
			}
		}
	}()
}

// netOff stops the network record.
func (s *server) netOff(why string) {
	s.netMu.Lock()
	stop := s.netCancel
	s.netCancel = nil
	s.netMu.Unlock()
	if stop != nil {
		stop()
		s.netRec.Stopped(time.Now(), why)
	}
}

// syncRecorder works out the real stores again and makes sure they're
// watched. It runs after every reload and health check, in the background:
// putting watches on folders can take a moment (on Windows, an audit rule
// is passed on to every file in the folder).
func (s *server) syncRecorder(st *config.State) {
	go s.safe("flight recorder", func() {
		s.recMu.Lock()
		defer s.recMu.Unlock()
		s.mu.Lock()
		cfg := s.cfg
		s.mu.Unlock()
		if cfg == nil {
			return
		}
		if cfg.NoRecorder {
			s.rec.SetStores(nil, nil)
			s.watchStores(nil)
			s.netOff("it's switched off (`aba recorder on`)")
			return
		}
		s.netOn()
		planted := map[string]bool{}
		for id, bs := range st.Baits {
			if bs.Status != "retired" {
				planted[id] = true
			}
		}
		stores := baits.RealStores(cfg.User, planted)
		isBait := func(p string) bool { _, ok := s.eng.IsBait(p); return ok }
		s.rec.SetStores(stores, isBait)
		now := time.Now()
		why, gap := s.watchStores(stores)
		for _, store := range stores {
			switch {
			case len(store.Dirs()) == 0:
				s.rec.Absent(store.ID, now)
			case s.recWhy != "":
				s.rec.NotWatching(store.ID, now, s.recWhy)
			case why[store.ID] != "":
				s.rec.NotWatching(store.ID, now, why[store.ID])
			default:
				if gap[store.ID] != "" && !s.synced.IsZero() {
					// Opens between the last check and now may have been
					// missed: the watch ends there, and starts again now.
					s.rec.NotWatching(store.ID, s.synced, gap[store.ID])
				}
				s.rec.Watching(store.ID, len(store.Resolve()), now)
			}
		}
		s.synced = now
		s.rec.Prune()
	})
}

// recorderHealth says how the recorder is doing, for `aba doctor`.
func (s *server) recorderHealth(add func(name string, ok bool, detail string)) {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	switch {
	case cfg == nil:
	case cfg.NoRecorder:
		add("Flight recorder", true, "off (`aba recorder on` to switch it on): after a catch, ABA can't say whether the program had been at your real data")
	case s.recWhy != "":
		add("Flight recorder", false, s.recWhy)
	default:
		st := s.rec.Status()
		add("Flight recorder", st.Stores == 0 || st.Watched > 0,
			fmtRecorder(st))
		ns := s.netRec.Status()
		switch {
		case ns.Running:
			add("Network record", true, fmt.Sprintf("on since %s: notes which programs send data off this %s, so after a catch ABA can say whether anything left (it never alerts on its own)",
				ns.Since.Local().Format("Jan 2 15:04"), platform.PC))
		case runtime.GOOS != "windows":
			// Not there yet: nothing to check.
		default:
			add("Network record", false, "not running: "+ns.Why+". After a catch, ABA can't say whether anything left this "+platform.PC)
		}
	}
}

func fmtRecorder(st recorder.Status) string {
	if st.Stores == 0 {
		return "on; ABA found none of your browsers, wallets or keys to watch"
	}
	return fmt.Sprintf("on, watching %d of the %d places your passwords, cookies, wallets and keys are kept (it never alerts on its own)", st.Watched, st.Stores-st.Absent)
}

// Autopsy is engine.Ops.Autopsy.
func (s *server) Autopsy(c autopsy.Case) *alerts.Autopsy {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cfg == nil {
		return nil
	}
	c.User = cfg.User
	st, _ := config.LoadState()
	c.BaitFiles = map[string]string{}
	if st != nil {
		for _, bs := range st.Baits {
			for _, f := range bs.Files {
				c.BaitFiles[f.Path] = bs.Name
			}
		}
	}
	c.Stores = s.rec.Stores()
	if len(c.Stores) == 0 && st != nil {
		planted := map[string]bool{}
		for id, bs := range st.Baits {
			if bs.Status != "retired" {
				planted[id] = true
			}
		}
		c.Stores = baits.RealStores(cfg.User, planted)
	}
	h := autopsy.SystemHooks(!cfg.NoMemoryImage)
	h.Recorder = func(q recorder.Query) (recorder.Result, string) {
		res := s.rec.Query(q)
		switch {
		case cfg.NoRecorder:
			return res, "it's switched off (`aba recorder on`)"
		case s.recWhy != "":
			return res, s.recWhy
		}
		return res, ""
	}
	h.Network = func(q netrec.Query) (netrec.Result, string) {
		res := s.netRec.Query(q)
		if cfg.NoRecorder {
			return res, "it's switched off (`aba recorder on`)"
		}
		return res, ""
	}
	h.Settle = settle
	h.Logf = s.log.Printf
	return autopsy.Run(c, h)
}

// NotifyAutopsy tells the person, on the desktop and the phone, that the
// caught program had read real data, and what to do first.
func (s *server) NotifyAutopsy(a *alerts.Alert) {
	// The app shows the report: open it again (an open app turns to this
	// alert), with a toast. Without the app: the autopsy popup.
	if s.openApp(a) {
		ta := notify.ToastAlert(a)
		ta.Title = "ABA: what " + a.ExeName() + " had already opened"
		if a.Autopsy != nil && a.Autopsy.Sent == alerts.SentNothing {
			ta.Title = "ABA: " + a.ExeName() + " was stopped before it sent anything"
		}
		ta.Summary = "The full report is open in ABA."
		if b, err := json.Marshal(notify.Envelope{Alert: ta, ToastOnly: true}); err == nil {
			session.LaunchWithInput(s.cliExe, b, "notify")
		}
	} else if b, err := json.Marshal(notify.Envelope{Alert: a, Autopsy: true}); err == nil {
		if _, err := session.LaunchWithInput(s.cliExe, b, "notify"); err != nil {
			s.log.Printf("desktop notify (autopsy): %v", err)
		}
	}
	s.mu.Lock()
	sec, dial := s.secrets, s.dial
	s.mu.Unlock()
	if sec == nil || !sec.Phone.Enabled() {
		return
	}
	msg := notify.FromAutopsy(a)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := notify.NewSender(sec.Phone, dial).Send(ctx, msg); err != nil {
			s.log.Printf("phone alert (autopsy) failed for %s: %v", a.ID, err)
		}
	}()
}
