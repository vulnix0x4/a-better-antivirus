package service

// The miner trap on Windows (package minertrap): the service runs the DNS
// responder and the fake pool, keeps the redirect in place, and hands each
// program caught logging in to mine to the engine.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/update"
)

var miners struct {
	sync.Mutex
	trap     *minertrap.Trap
	listErr  error       // why the list of pools couldn't be read, last time
	fetching atomic.Bool // a download of the list is under way
	caught   sync.Mutex  // one catch at a time through the engine, so repeats join one alert
}

// minerTrap makes the trap run when on is true, and takes it away (the
// redirect too) when it's false. It's called on every reload and every
// minute, so a redirect that was removed, or a listener that couldn't start,
// is put right.
func (s *server) minerTrap(on bool) {
	miners.Lock()
	defer miners.Unlock()
	if !on {
		if miners.trap != nil {
			miners.trap.Stop()
			miners.trap = nil
			s.log.Printf("miner trap: off")
		}
		if n, err := minertrap.Remove(); n > 0 || err != nil {
			s.log.Printf("miner trap: removed %d redirect rule(s) (%v)", n, err)
		}
		return
	}
	listed := s.loadPools()
	if miners.trap == nil {
		t := &minertrap.Trap{Addr: minertrap.AddrIP, DNSPort: 53, Ports: minertrap.Ports, OnCatch: s.onMiner, Logf: s.log.Printf,
			OnQuery: func(q minertrap.Query) {
				if q.Pool != "" && s.once("miner-lookup|"+q.Name, time.Hour) {
					s.log.Printf("miner trap: %s was looked up (sent to the fake pool)", q.Name)
				}
			}}
		if err := t.Start(); err != nil {
			if s.once("miner-start|"+err.Error(), 6*time.Hour) {
				s.log.Printf("miner trap: can't start: %v", err)
			}
		} else {
			miners.trap = t
			st := t.Status()
			s.log.Printf("miner trap: on: DNS at %s, fake pool on %d ports", st.DNS, len(st.Pool))
			if len(st.Failed) > 0 {
				s.log.Printf("miner trap: couldn't listen on: %s", strings.Join(st.Failed, "; "))
			}
		}
	}
	if !listed {
		return // the redirect stays as it is until there's a list to check it against
	}
	if changed, err := minertrap.Apply(); err != nil {
		if s.once("miner-nrpt|"+err.Error(), 6*time.Hour) {
			s.log.Printf("miner trap: redirect: %v", err)
		}
	} else if changed {
		s.log.Printf("miner trap: %d pool names now lead to the fake pool", len(minertrap.Pools()))
	}
}

// loadPools reads the list of mining pools installed next to ABA, and says
// whether there was one. Without it (an update from a version that had the
// list built in, or an install from the bare exe), the trap goes on with the
// names its redirect already sends to it, and the service fetches the list
// of its own release, checked against the release's signed checksums.
func (s *server) loadPools() bool {
	_, err := minertrap.LoadPools()
	miners.listErr = err
	if err == nil {
		return true
	}
	if s.once("miner-pools|"+err.Error(), 6*time.Hour) {
		s.log.Printf("miner trap: %v", err)
	}
	if len(minertrap.Pools()) == 0 {
		if old := minertrap.InstalledPools(); len(old) > 0 {
			minertrap.SetPools(old)
			s.log.Printf("miner trap: answering for the %d pool names already in the redirect until the list is back", len(old))
		}
	}
	if update.Updatable(Version) && s.once("miner-pools-fetch", time.Hour) && miners.fetching.CompareAndSwap(false, true) {
		go func() {
			defer miners.fetching.Store(false)
			if err := fetchPools(); err != nil {
				s.log.Printf("miner trap: fetching the list of mining pools of %s: %v", Version, err)
				return
			}
			s.log.Printf("miner trap: fetched the list of mining pools of %s (signature and checksum verified)", Version)
		}()
	}
	return false
}

// fetchPools downloads this version's list of mining pools and installs it.
func fetchPools() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, err := update.Pools(ctx, Version)
	if err != nil {
		return err
	}
	if _, err := minertrap.ParsePools(b); err != nil {
		return err
	}
	tmp := minertrap.PoolsFile() + ".part"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, minertrap.PoolsFile())
}

// minerTrapStop stops listening as the service stops. The redirect stays:
// until the service is back, pool names lead nowhere.
func (s *server) minerTrapStop() {
	miners.Lock()
	defer miners.Unlock()
	if miners.trap != nil {
		miners.trap.Stop()
		miners.trap = nil
	}
}

// onMiner reports a program caught logging in to mine. The fake pool holds
// its connection meanwhile and gives it nothing to do.
func (s *server) onMiner(c minertrap.Catch) {
	miners.caught.Lock()
	defer miners.caught.Unlock()
	pool, sure := c.Pool()
	m := &detect.Mine{Pool: pool, PoolSure: sure, Port: int(c.Server.Port()), TLS: c.TLS, Method: c.Login.Method,
		Wallet: c.Login.Wallet, Pass: c.Login.Pass, Agent: c.Login.Agent, Algo: c.Login.Algo}
	pid, err := procinfo.ConnOwner(c.Client, c.Server)
	s.log.Printf("miner trap: %s logged in to mine (pid %d, pool %q, port %d, tls %v, wallet %q, agent %q)",
		c.Client, pid, pool, m.Port, c.TLS, m.Wallet, m.Agent)
	if pid == uint32(os.Getpid()) {
		return
	}
	if pid == 0 {
		if tr := s.PendingTest(); tr != nil && tr.Miner {
			s.log.Printf("miner trap: test: the login wasn't pinned on a program (%v)", err)
			return
		}
		// Gone already, between its login and the look-up.
		summary := "A program logged in to mine cryptocurrency at ABA's fake mining pool, but it was gone before ABA could tell which one it was. A miner is running on this " + platform.PC + "."
		if m.Wallet != "" {
			summary += " The wallet it mines for: " + m.Wallet + "."
		}
		s.eng.SystemAlert(alerts.KindMiner, config.TierCritical, "A crypto miner is running on this "+platform.PC, summary,
			[]alerts.BaitHit{{ID: engine.MinerTrap, Name: engine.MinerTrapName, Path: engine.MinePlace(m), Access: "mine", Time: c.Time}})
		return
	}
	oa := &detect.Access{Time: c.Time, Op: detect.OpMine, PID: pid, Mine: m}
	oa.Image, _ = procinfo.ImagePath(pid)
	oa.UserID, _ = procinfo.UserID(pid)
	s.eng.HandleAccess(oa)
}

// minerHealth is the trap's line in the health check.
func (s *server) minerHealth(add func(name string, ok bool, detail string)) {
	miners.Lock()
	t, listErr := miners.trap, miners.listErr
	miners.Unlock()
	n, err := minertrap.Installed()
	switch {
	case listErr != nil:
		add("Miner trap", false, fmt.Sprintf("%v (the service fetches it again every hour; ABA-Setup.exe brings it too)", listErr))
	case t == nil:
		add("Miner trap", false, "the fake pool isn't running (see the service log)")
	case t.Status().DNS == "":
		add("Miner trap", false, "its DNS responder couldn't start on "+minertrap.Addr+" port 53 (something else holds it): pool names lead nowhere, but nothing is caught")
	case err != nil || n != minertrap.Expected():
		add("Miner trap", false, fmt.Sprintf("the redirect isn't fully in place (%d of %d rules)", n, minertrap.Expected()))
	default:
		add("Miner trap", true, fmt.Sprintf("%d pool names lead to the fake pool (%d ports)", len(minertrap.Pools()), len(t.Status().Pool)))
	}
}
