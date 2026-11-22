package service

// The clipboard bait on Windows: a helper (`aba clipboard-guard`) in each
// session someone is using, run as SYSTEM so that what it watches can't
// touch it. It reports clippers it catches here, over its output, and waits
// for the engine to deal with each before letting it go.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/clipbait"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/engine"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

var clipGuards struct {
	sync.Mutex
	running map[uint32]*session.Helper // by session
}

// clipboardBait makes sure a clipboard guard runs in every active session
// when on is true, and none when it's false. It's called on every reload and
// every minute, as people log on and off.
func (s *server) clipboardBait(on bool) {
	clipGuards.Lock()
	defer clipGuards.Unlock()
	if clipGuards.running == nil {
		clipGuards.running = map[uint32]*session.Helper{}
	}
	want := map[uint32]bool{}
	if on {
		ids, err := session.ActiveSessions()
		if err != nil {
			s.log.Printf("clipboard bait: listing sessions: %v", err)
		}
		for _, id := range ids {
			want[id] = true
		}
	}
	for id, h := range clipGuards.running {
		if !want[id] || h.Exited() {
			h.Stop() // it puts the clipboard back before it goes
			delete(clipGuards.running, id)
		}
	}
	for id := range want {
		if clipGuards.running[id] != nil {
			continue
		}
		h, err := session.StartSystem(id, s.cliExe, "clipboard-guard")
		if err != nil {
			if s.once(fmt.Sprintf("clipguard|%d|%v", id, err), 6*time.Hour) {
				s.log.Printf("clipboard bait: starting the guard in session %d: %v", id, err)
			}
			continue
		}
		s.log.Printf("clipboard bait: guarding session %d (pid %d)", id, h.PID)
		clipGuards.running[id] = h
		go s.safe("clipboard guard", func() { s.listenClipGuard(h) })
	}
}

// listenClipGuard reads what a guard reports, until it ends.
func (s *server) listenClipGuard(h *session.Helper) {
	sc := bufio.NewScanner(h.Out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var msg struct {
			Log     string            `json:"log"`
			Finding *clipbait.Finding `json:"finding"`
		}
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			line := sc.Text()
			if len(line) > 300 {
				line = line[:300] + "…"
			}
			s.log.Printf("clipboard guard (session %d): %s", h.Session, line)
			continue
		}
		if msg.Log != "" {
			s.log.Printf("session %d: %s", h.Session, msg.Log)
		}
		if f := msg.Finding; f != nil {
			s.safe("clipper", func() { s.onClipper(f) })
			fmt.Fprintln(h.In, "done") // frozen (or not, as configured): the guard may let go
		}
	}
}

// onClipper raises the alert for a clipper a guard caught, and responds as
// configured, like any critical stealer. The guard is keeping it paused
// meanwhile, so freezing it first isn't a race.
func (s *server) onClipper(f *clipbait.Finding) {
	sw := &detect.Swap{Coin: string(f.Coin), Bait: f.Bait, Replacement: f.Replacement, How: f.How, LatencyMS: f.Latency.Milliseconds()}
	s.log.Printf("clipboard bait: %s bait %s swapped for %q in %v by pid %d (%s)", f.Coin, f.Bait, f.Replacement, f.Latency, f.PID, f.How)
	if f.PID == 0 {
		// Swapped for an address, so a clipper is running, but nothing could
		// be pinned down (it was interrupted, or hides too well).
		var who []string
		for _, pid := range f.Suspects {
			img, _ := procinfo.ImagePath(pid)
			who = append(who, fmt.Sprintf("%s (pid %d)", img, pid))
		}
		summary := "A program swapped the fake wallet address ABA put on the clipboard for " + f.Replacement +
			", which only clippers do, but ABA couldn't tell which program it was. Until it's found, check every wallet address you paste, character by character, before you send anything."
		if len(who) > 0 {
			summary += " Windows pointed at: " + strings.Join(who, ", ") + "."
		}
		s.eng.SystemAlert(alerts.KindClipper, config.TierCritical, "A clipper is running on this PC", summary,
			[]alerts.BaitHit{{ID: engine.ClipboardBait, Name: "Clipboard (a fake wallet address)", Path: "the clipboard", Access: "swap", Time: f.Time}})
		return
	}
	oa := &detect.Access{Time: f.Time, Op: detect.OpSwap, PID: f.PID, Swap: sw}
	oa.Image, _ = procinfo.ImagePath(f.PID)
	oa.UserID, _ = procinfo.UserID(f.PID)
	s.eng.HandleAccess(oa)
}
