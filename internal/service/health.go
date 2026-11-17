package service

import (
	"fmt"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// healthCheck keeps the tripwire armed: auditing on, baits present with their
// audit rules, decoys retired when the real app appears, Recent files clean.
func (s *server) healthCheck(startup bool) {
	s.mu.Lock()
	cfg, sec := s.cfg, s.secrets
	s.mu.Unlock()
	if cfg == nil {
		return
	}
	var health []config.HealthItem
	add := func(name string, ok bool, detail string) {
		health = append(health, config.HealthItem{Name: name, OK: ok, Detail: detail})
	}

	// 1. System audit policy.
	if changed, err := winsec.EnsureFileSystemAudit(); err != nil {
		add("File auditing", false, err.Error())
	} else {
		add("File auditing", true, "on")
		if changed && !startup {
			s.eng.SystemAlert(alerts.KindAuditDisabled, config.TierWarn, "File auditing was switched off",
				"Something turned off Windows file auditing, which blinds ABA. It has been turned back on. Malware with admin rights does this; so do some 'optimizer' tools.", nil)
		}
	}

	// 2. Baits.
	var retire []string
	var raised []func()
	g := (*baits.Gen)(nil)
	ok, total := 0, 0
	config.UpdateState(func(st *config.State) error {
		g = baits.GenFromPersona(st.Persona)
		if sec != nil {
			for _, t := range sec.Canary.Tokens {
				g.Canary[t.Kind] = t.Data
			}
		}
		for id, bs := range st.Baits {
			if bs.Status == "retired" {
				continue
			}
			total++
			spec, known := baits.SpecByID(cfg, id)
			if known && spec.Kind != baits.KindFile {
				if m := baits.InstalledMarker(spec, cfg.User); m != "" {
					retire = append(retire, id)
					name := bs.Name
					raised = append(raised, func() {
						s.eng.SystemAlert(alerts.KindDecoyRetired, config.TierInfo, "Retired decoy: "+name,
							"The real app is now installed ("+m+"), so ABA removed its fake data to stay out of its way.", nil)
					})
					continue
				}
			}
			probs := baits.Check(bs)
			bs.LastCheck = time.Now()
			if len(probs) == 0 {
				bs.Status, bs.StatusNote = "ok", ""
				ok++
				continue
			}
			var hits []alerts.BaitHit
			kind, title := "", ""
			for _, p := range probs {
				switch p.Kind {
				case "missing":
					kind, title = alerts.KindBaitMissing, "A bait disappeared: "+bs.Name
				case "no-audit":
					if kind == "" {
						kind, title = alerts.KindAuditRemoved, "A bait lost its tripwire: "+bs.Name
					}
				}
				hits = append(hits, alerts.BaitHit{ID: id, Name: bs.Name, Path: p.File, Access: p.Kind, Time: time.Now()})
			}
			if known {
				if err := baits.Repair(bs, spec, cfg.User, g, probs); err != nil {
					bs.Status, bs.StatusNote = "error", err.Error()
					continue
				}
			}
			bs.Status, bs.StatusNote = "ok", "repaired "+time.Now().Format("Jan 2 15:04")
			ok++
			if kind != "" && !startup {
				k, t, h := kind, title, hits
				raised = append(raised, func() {
					s.eng.SystemAlert(k, config.TierWarn, t, "ABA restored it. If you didn't delete or edit it, something else did.", h)
				})
			}
		}
		for _, id := range retire {
			baits.Retire(st, cfg.User, id, "real app installed")
		}
		// Forget frozen processes that no longer exist.
		var live []config.FrozenProcess
		for _, f := range st.Frozen {
			if procinfo.Alive(f.PID, f.CreateTime) {
				live = append(live, f)
			}
		}
		st.Frozen = live
		if st.Persona == nil {
			st.Persona = g.Persona()
		}
		return nil
	})
	for _, f := range raised {
		f()
	}
	if len(retire) > 0 {
		s.reload()
	}
	add("Baits", ok == total, fmt.Sprintf("%d of %d healthy", ok, total))

	// 3. Recent files: shortcuts to baits invite apps like Copilot to read them.
	if cfg.CleanRecent {
		st, _ := config.LoadState()
		if st != nil {
			if removed := baits.CleanRecent(cfg.User.RoamingAppData, baits.Index(st)); len(removed) > 0 {
				s.log.Printf("removed %d Recent-files shortcut(s) to baits", len(removed))
			}
		}
	}

	// 4. Network guard visibility.
	if ns, err := netguard.GetStatus(); err != nil {
		add("Network guard", false, err.Error())
	} else if ns.Isolated {
		add("Network guard", true, "PC is ISOLATED (run `aba release` when safe)")
	} else {
		add("Network guard", true, fmt.Sprintf("ready (%d active rules)", ns.Rules))
	}

	config.UpdateState(func(st *config.State) error {
		st.Health = health
		st.Heartbeat = time.Now()
		return nil
	})
}
