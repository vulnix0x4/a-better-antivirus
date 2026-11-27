// Package doctor diagnoses a ABA installation and fixes what it can.
//
// The checks are the same on every operating system, except the one for what
// the OS needs switched on to notice bait reads, and the list of sync and
// backup tools to look for: doctor_<os>.go.
package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

type Level int

const (
	OK Level = iota
	Note
	Warning
	Problem
)

type Result struct {
	Level  Level
	Name   string
	Detail string
	Fix    string // command or instruction
}

// Run performs all checks. Some need admin; they're reported as such otherwise.
func Run() []Result {
	var out []Result
	add := func(l Level, name, detail, fix string) { out = append(out, Result{l, name, detail, fix}) }
	admin := procinfo.SelfElevated()

	cfg, err := config.LoadConfig()
	if err != nil {
		add(Problem, "Installed", err.Error(), "aba install")
		return out
	}
	add(OK, "Installed", "since "+cfg.InstalledAt.Format("Jan 2, 2006")+" for "+cfg.User.Name, "")
	st, _ := config.LoadState()

	// Binary version vs installed.
	self, _ := os.Executable()
	if _, err := os.Stat(paths.InstalledService()); err != nil {
		add(Problem, "Program files", "missing "+paths.InstalledService(), "aba install")
	} else if !paths.Under(self, paths.InstallDir()) {
		add(Note, "Program files", "you're running a copy from "+filepath.Dir(self)+"; the installed one is in "+paths.InstallDir(), "")
	}

	// Service.
	s, err := svcctl.Status()
	switch {
	case err != nil:
		add(Problem, "Service", err.Error(), "")
	case s == svcctl.Running:
		if st != nil && time.Since(st.Heartbeat) > 3*time.Minute {
			add(Warning, "Service", "running but no heartbeat since "+st.Heartbeat.Format("15:04")+" (see "+paths.LogFile()+")", "aba doctor --fix")
		} else {
			add(OK, "Service", "running", "")
		}
	default:
		add(Problem, "Service", string(s), "aba doctor --fix")
	}

	// What the operating system needs switched on to notice bait reads at all
	// (on Windows, the audit policy).
	checkDetection(admin, st, add)

	// Baits.
	if st != nil {
		missing, noAudit, retired, total := 0, 0, 0, 0
		for _, bs := range st.Baits {
			if bs.Status == "retired" {
				retired++
				continue
			}
			total++
			for _, f := range bs.Files {
				if _, err := os.Stat(f.Path); err != nil {
					missing++
				} else if admin && f.Audit {
					if ok, _ := baits.HasTripwire(f.Path); !ok {
						noAudit++
					}
				}
			}
		}
		switch {
		case missing > 0:
			add(Warning, "Baits", fmt.Sprintf("%d file(s) missing (the service restores them every 5 minutes)", missing), "aba doctor --fix")
		case noAudit > 0:
			add(Warning, "Baits", fmt.Sprintf(lostTripwire, noAudit), "aba doctor --fix")
		default:
			d := fmt.Sprintf("%d active", total)
			if retired > 0 {
				d += fmt.Sprintf(", %d retired (you installed the real app)", retired)
			}
			if !admin {
				d += verifyHint
			}
			add(OK, "Baits", d, "")
		}

		// Recent files.
		idx := baits.Index(st)
		recent := recentFolder(cfg.User)
		n := 0
		if entries, err := os.ReadDir(recent); err == nil {
			for _, e := range entries {
				if b, err := os.ReadFile(filepath.Join(recent, e.Name())); err == nil {
					if _, hit := idx[paths.Key(baits.LnkTarget(b))]; hit {
						n++
					}
				}
			}
		}
		if recent == "" {
			// nothing of the kind on this system
		} else if n > 0 {
			add(Warning, "Recent files", fmt.Sprintf("%d shortcut(s) point at baits; apps like Copilot read these", n), "aba doctor --fix")
		} else {
			add(OK, "Recent files", "no shortcuts to baits", "")
		}

		// Active responses.
		if st.Isolation != nil {
			add(Warning, "Network", platform.Capital(platform.PC)+" is isolated since "+st.Isolation.Since.Format("Jan 2 15:04"), "aba release")
		}
		if len(st.Frozen) > 0 {
			add(Warning, "Frozen processes", fmt.Sprintf("%d still frozen", len(st.Frozen)), "aba alerts")
		}
	}

	// Sync / backup software that reads files.
	if snap, err := procinfo.Snapshot(); err == nil {
		seen := map[string]bool{}
		for _, e := range snap {
			if name, ok := syncTools[strings.ToLower(e.Exe)]; ok && name != "" && !seen[name] {
				seen[name] = true
			}
		}
		if len(seen) > 0 {
			var names []string
			for n := range seen {
				names = append(names, n)
			}
			synced := ""
			for _, d := range []string{cfg.User.Desktop, cfg.User.Documents} {
				if strings.Contains(strings.ToLower(d), "onedrive") {
					synced = " Your " + filepath.Base(d) + " folder is synced by OneDrive, so OneDrive will read baits there."
				}
			}
			add(Note, "Sync & backup", strings.Join(names, ", ")+" running: if they trip baits, learning mode suggests an ignore rule."+synced, "aba learn")
		}
	}

	// Notifications.
	if cfg.Learning(time.Now()) {
		add(Note, "Learning mode", Until(cfg.LearningUntil)+": only critical readers are stopped, the rest just raise an alert", "aba learn")
	}
	checkTraps(cfg, add)
	if admin {
		if sec, err := config.LoadSecrets(); err == nil {
			if sec.Phone.Enabled() {
				add(OK, "Phone alerts", sec.Phone.Describe(), "aba phone test")
			} else {
				add(Note, "Phone alerts", "off", "aba configure")
			}
		}
	}
	return out
}

// checkTraps: the clipboard bait and the miner trap, where they exist.
func checkTraps(cfg *config.Config, add func(l Level, name, detail, fix string)) {
	if runtime.GOOS == "windows" {
		if cfg.ClipboardBait {
			add(OK, "Clipboard bait", "on: clippers are caught", "")
		} else {
			add(Note, "Clipboard bait", "off", "aba clipboard on")
		}
	}
	if !minertrap.Supported() {
		return
	}
	n, err := minertrap.Installed()
	_, listErr := minertrap.LoadPools()
	want := minertrap.Expected()
	switch {
	case err != nil:
		add(Warning, "Miner trap", "can't read the redirect: "+err.Error(), "")
	case cfg.MinerTrap && listErr != nil:
		add(Warning, "Miner trap", fmt.Sprintf("on, but %v. The service fetches it again every hour; ABA-Setup.exe brings it too", listErr), "")
	case cfg.MinerTrap && n == want:
		add(OK, "Miner trap", fmt.Sprintf("on: %d mining pools' names lead to ABA's fake pool", len(minertrap.Pools())), "")
	case cfg.MinerTrap:
		add(Warning, "Miner trap", fmt.Sprintf("on, but the redirect isn't fully in place (%d of %d rules): the service puts it back within a minute", n, want), "aba doctor --fix")
	case n > 0:
		add(Warning, "Miner trap", fmt.Sprintf("off, but %d of its redirect rules are left", n), "aba miners off")
	default:
		add(Note, "Miner trap", "off", "aba miners on")
	}
}

// Until is duplicated from ui to keep this package UI-free.
func Until(t time.Time) string {
	d := time.Until(t)
	if d > 48*time.Hour {
		return fmt.Sprintf("%d days left", int(d.Hours()/24+0.5))
	}
	return fmt.Sprintf("%dh left", int(d.Hours())+1)
}

// Fix repairs what it can (admin).
func Fix() []string {
	var did []string
	did = append(did, fixDetection()...)
	cfg, err := config.LoadConfig()
	if err != nil {
		return did
	}
	if st, err := config.LoadState(); err == nil {
		if r := baits.CleanRecent(cfg.User.RoamingAppData, baits.Index(st)); len(r) > 0 {
			did = append(did, fmt.Sprintf("removed %d Recent-files shortcut(s) to baits", len(r)))
		}
	}
	if minertrap.Supported() {
		if _, err := minertrap.LoadPools(); cfg.MinerTrap && err != nil {
			did = append(did, "could not check the miner trap's redirect: "+err.Error())
		} else if cfg.MinerTrap {
			if changed, err := minertrap.Apply(); err != nil {
				did = append(did, "could not put the miner trap's redirect back: "+err.Error())
			} else if changed {
				did = append(did, "put the miner trap's redirect back")
			}
		} else if n, _ := minertrap.Remove(); n > 0 {
			did = append(did, fmt.Sprintf("removed %d redirect rule(s) the miner trap left", n))
		}
	}
	if s, _ := svcctl.Status(); s != svcctl.Running {
		if err := svcctl.Start(); err != nil {
			did = append(did, "could not start the service: "+err.Error())
		} else {
			did = append(did, "service started")
		}
	}
	return did
}
