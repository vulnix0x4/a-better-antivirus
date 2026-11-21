package doctor

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/fanwatch"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// checkDetection checks what Linux needs for bait opens to be noticed and
// for a freeze to hold. The marks on the bait files live in the service, so
// what it last recorded is shown; as root, the kernel is also asked directly
// whether it can do this at all.
func checkDetection(admin bool, st *config.State, add func(l Level, name, detail, fix string)) {
	seen := false
	if st != nil {
		for _, h := range st.Health {
			if h.Name != "Watching baits" && h.Name != "Freezer" && h.Name != "Instant freeze" {
				continue
			}
			seen = seen || h.Name == "Watching baits"
			l := OK
			if !h.OK {
				l = Problem
				if h.Name == "Freezer" {
					l = Warning
				}
			}
			add(l, h.Name, h.Detail+" (as of the service's last check)", "")
		}
	}
	if !admin || seen {
		return
	}
	// The service hasn't reported yet: ask the kernel.
	w, err := fanwatch.New()
	if err != nil {
		add(Problem, "Watching baits", "this kernel won't let ABA watch files: "+err.Error(), "")
		return
	}
	w.Close()
	go w.Run()
	add(OK, "Watching baits", "this kernel can; the service hasn't reported yet", "")
	if err := procinfo.FreezerStatus(); err != nil {
		add(Warning, "Freezer", "no cgroup v2 freezer: "+err.Error(), "")
	}
}

// fixDetection: nothing in the system has to be switched on for detection on
// Linux, so there is nothing to put right here. (A service that isn't
// running is started by the shared part of `aba doctor --fix`.)
func fixDetection() []string { return nil }

// syncTools are sync and backup programs (process name, lowercase -> product):
// software that legitimately reads the files in your folders.
var syncTools = map[string]string{
	"syncthing": "Syncthing", "dropbox": "Dropbox", "nextcloud": "Nextcloud", "owncloud": "ownCloud", "megasync": "MEGA",
	"insync": "Insync", "rclone": "rclone", "restic": "restic", "borg": "Borg", "duplicity": "Duplicity", "deja-dup-monitor": "Backups (Déjà Dup)",
	"timeshift": "Timeshift", "backintime": "Back In Time", "kopia": "Kopia", "onedrive": "OneDrive",
}
