package doctor

import (
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// checkDetection checks what macOS needs for bait opens to be noticed: the
// service has Full Disk Access and eslogger runs. That's only known inside
// the service, so what it last recorded is shown, and whether it's watching
// right now.
func checkDetection(admin bool, st *config.State, add func(l Level, name, detail, fix string)) {
	const fix = "System Settings > Privacy & Security > Full Disk Access: switch on \"" + paths.ServiceDisplayName + "\" (`sudo aba doctor --fix` opens it)"
	seen := false
	if st != nil {
		for _, h := range st.Health {
			if h.Name != "Watching baits" && h.Name != "Finder copies" {
				continue
			}
			seen = seen || h.Name == "Watching baits"
			l := OK
			switch {
			case h.OK:
			case h.Name == "Finder copies":
				l = Warning
			default:
				l = Problem
			}
			hint := ""
			if !h.OK && h.Name == "Watching baits" {
				hint = fix
			}
			add(l, h.Name, h.Detail+" (as of the service's last check)", hint)
		}
	}
	if seen {
		return
	}
	if svcctl.Watching() {
		add(OK, "Watching baits", "on; the service hasn't reported its check yet", "")
	} else if s, _ := svcctl.Status(); s == svcctl.Running {
		add(Problem, "Watching baits", "the service runs but isn't watching the baits: it most likely lacks Full Disk Access", fix)
	}
}

// fixDetection opens Full Disk Access for the person at the screen: only
// they can switch it on.
func fixDetection() []string {
	if svcctl.Watching() {
		return nil
	}
	if err := svcctl.OpenFullDiskAccess(); err != nil {
		return []string{"couldn't open Full Disk Access (" + err.Error() + "): open System Settings > Privacy & Security > Full Disk Access and switch on \"" + paths.ServiceDisplayName + "\""}
	}
	svcctl.Send(svcctl.CheckNow)
	return []string{"opened Full Disk Access in System Settings: switch on \"" + paths.ServiceDisplayName + "\""}
}

// syncTools are sync and backup programs (process name, lowercase -> product):
// software that legitimately reads the files in your folders.
var syncTools = map[string]string{
	"dropbox": "Dropbox", "google drive": "Google Drive", "onedrive": "OneDrive", "box": "Box", "megaclient": "MEGA",
	"pcloud drive": "pCloud", "syncthing": "Syncthing", "resilio sync": "Resilio Sync", "nextcloud": "Nextcloud",
	"arq": "Arq", "arqagent": "Arq", "bztransmit": "Backblaze", "bzfilelist": "Backblaze", "crashplanservice": "CrashPlan",
	"carbon copy cloner": "Carbon Copy Cloner", "superduper!": "SuperDuper!", "chronosync": "ChronoSync",
	"rclone": "rclone", "restic": "restic", "borg": "Borg", "kopia": "Kopia", "backupd": "Time Machine",
}
