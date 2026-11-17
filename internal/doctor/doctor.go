// Package doctor diagnoses a ABA installation and fixes what it can.
package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
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
	admin := winsec.IsElevated()

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

	// Audit policy.
	if admin {
		if f, err := winsec.FileSystemAudit(); err != nil {
			add(Problem, "File auditing", err.Error(), "")
		} else if f&winsec.AuditSuccess == 0 {
			add(Problem, "File auditing", "OFF: reads can't be detected", "aba doctor --fix")
		} else {
			add(OK, "File auditing", "on", "")
		}
	} else if st != nil {
		for _, h := range st.Health {
			if h.Name == "File auditing" {
				l := OK
				if !h.OK {
					l = Problem
				}
				add(l, "File auditing", h.Detail+" (as of the service's last check)", "")
			}
		}
	}

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
					if ok, _ := winsec.HasBaitAudit(f.Path); !ok {
						noAudit++
					}
				}
			}
		}
		switch {
		case missing > 0:
			add(Warning, "Baits", fmt.Sprintf("%d file(s) missing (the service restores them every 5 minutes)", missing), "aba doctor --fix")
		case noAudit > 0:
			add(Warning, "Baits", fmt.Sprintf("%d file(s) lost their audit rule", noAudit), "aba doctor --fix")
		default:
			d := fmt.Sprintf("%d active", total)
			if retired > 0 {
				d += fmt.Sprintf(", %d retired (you installed the real app)", retired)
			}
			if !admin {
				d += "; run as admin to verify audit rules"
			}
			add(OK, "Baits", d, "")
		}

		// Recent files.
		idx := baits.Index(st)
		recent := filepath.Join(cfg.User.RoamingAppData, `Microsoft\Windows\Recent`)
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
		if n > 0 {
			add(Warning, "Recent files", fmt.Sprintf("%d shortcut(s) point at baits; apps like Copilot read these", n), "aba doctor --fix")
		} else {
			add(OK, "Recent files", "no shortcuts to baits", "")
		}

		// Active responses.
		if st.Isolation != nil {
			add(Warning, "Network", "PC is isolated since "+st.Isolation.Since.Format("Jan 2 15:04"), "aba release")
		}
		if len(st.Frozen) > 0 {
			add(Warning, "Frozen processes", fmt.Sprintf("%d still frozen", len(st.Frozen)), "aba alerts")
		}
	}

	// Sync / backup software that reads files.
	if snap, err := procinfo.Snapshot(); err == nil {
		known := map[string]string{
			"onedrive.exe": "OneDrive", "dropbox.exe": "Dropbox", "googledrivefs.exe": "Google Drive",
			"icloudckks.exe": "iCloud", "bztransmit.exe": "Backblaze", "bztransmit64.exe": "Backblaze",
			"crashplanservice.exe": "CrashPlan", "reflectbin.exe": "Macrium Reflect", "veeam.endpoint.service.exe": "Veeam",
			"syncthing.exe": "Syncthing", "megasync.exe": "MEGA", "everything.exe": "",
		}
		seen := map[string]bool{}
		for _, e := range snap {
			if name, ok := known[strings.ToLower(e.Exe)]; ok && name != "" && !seen[name] {
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
		add(Note, "Learning mode", Until(cfg.LearningUntil)+": alerts only, nothing is blocked", "aba learn")
	}
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
	if _, err := winsec.EnsureFileSystemAudit(); err == nil {
		did = append(did, "file auditing is on")
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return did
	}
	if st, err := config.LoadState(); err == nil {
		if r := baits.CleanRecent(cfg.User.RoamingAppData, baits.Index(st)); len(r) > 0 {
			did = append(did, fmt.Sprintf("removed %d Recent-files shortcut(s) to baits", len(r)))
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
