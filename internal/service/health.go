package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
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

	// 1. What the operating system needs switched on to notice bait reads at
	// all (on Windows, the system audit policy).
	s.detectionHealth(startup, add)

	// 2. Baits.
	var retire []string
	var raised []func()
	g := (*baits.Gen)(nil)
	ok, total := 0, 0
	// Work on a snapshot: checking and repairing ~40 files is slow (each open
	// also passes through instant freeze), and holding the state lock that long
	// once made `aba release` time out. Results are saved briefly at the end.
	st, err := config.LoadState()
	if err != nil {
		st = config.NewState()
	}
	{
		g = baits.GenFromPersona(st.Persona)
		if sec != nil {
			for _, t := range sec.Canary.Tokens {
				g.Canary[t.Kind] = t.Data
			}
		}
		retiring := baits.RecentlyRetired(st, retireLimit)
		for id, bs := range st.Baits {
			if bs.Status == "retired" {
				continue
			}
			total++
			spec, known := baits.SpecByID(cfg, id)
			// A fake profile inside a real browser that the browser has now taken
			// as one of its own (it reached that profile number): out of its way.
			if known && baits.Adopted(spec, cfg.User) && s.mayRetire(retiring, id, bs.Name) {
				retiring++
				retire = append(retire, id)
				name := bs.Name
				raised = append(raised, func() {
					s.eng.SystemAlert(alerts.KindDecoyRetired, config.TierWarn, "Retired bait: "+name,
						"The browser now uses that profile folder itself, so ABA removed its fake data from it. If you didn't just create a browser profile, something else registered it, to switch this bait off.", nil)
				})
				continue
			}
			if known && spec.Kind != baits.KindFile {
				if m, genuine := baits.Installed(spec, cfg.User); m != "" {
					name := bs.Name
					switch {
					case !genuine:
						// Something that looks like the app's program but isn't: the
						// cheap way to get ABA to remove a decoy by itself. Keep it.
						if s.once("fake|"+strings.ToLower(m), 24*time.Hour) {
							raised = append(raised, func() {
								s.eng.SystemAlert(alerts.KindTamper, config.TierCritical, "Something tried to get a decoy retired: "+name,
									m+" appeared, but it isn't the genuine app (it isn't signed by its publisher). A file like that is what you'd plant to make ABA remove its fake "+name+" data by itself, so ABA kept the decoy. If it's a build of the app you installed yourself, remove the decoy with `aba configure`.", nil)
							})
						}
					case !s.mayRetire(retiring, id, name):
						// A second one within a day: refused, and said so.
					default:
						retiring++
						retire = append(retire, id)
						raised = append(raised, func() {
							// A warning, so it reaches you (popup and phone): a bait is gone.
							s.eng.SystemAlert(alerts.KindDecoyRetired, config.TierWarn, "Retired decoy: "+name,
								"The real app is now installed ("+m+"), so ABA removed its fake data to stay out of its way. If you didn't install it, something else did, to switch this bait off.", nil)
						})
						continue
					}
				}
			}
			if startup && known {
				baits.Blend(bs, spec, cfg.User, g) // installs from older versions: see baits.Blend
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
		if len(retire) > 0 {
			s.guard(nil) // let go of the files about to be removed; reload re-arms the rest
		}
		for _, id := range retire {
			baits.Retire(st, cfg.User, id, "real app installed")
		}
	}
	checked := st
	config.UpdateState(func(st *config.State) error {
		for id, bs := range checked.Baits {
			// Skip baits added, removed or replaced while we were checking.
			if cur := st.Baits[id]; cur != nil && cur.CreatedAt.Equal(bs.CreatedAt) {
				st.Baits[id] = bs
			}
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
	} else {
		s.baitsChanged(checked) // a repaired bait is a new file
	}
	add("Baits", ok == total, fmt.Sprintf("%d of %d healthy", ok, total))
	if cfg.InstantFreeze {
		// A guard is down for a moment after each open (and during this check),
		// so "most of them" is healthy; one that stays down is reported by onBlocked.
		armed, want := s.guardCounts()
		add("Instant freeze", want > 0, fmt.Sprintf("on, guarding %d of %d bait files", armed, want))
	} else {
		add("Instant freeze", true, "off")
	}

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
	s.reconcileHolds()
	s.publish()
}
