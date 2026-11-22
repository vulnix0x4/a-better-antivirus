package doctor

import (
	"path/filepath"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// checkDetection checks the Windows audit policy: without "Audit File System"
// no bait read is ever logged.
func checkDetection(admin bool, st *config.State, add func(l Level, name, detail, fix string)) {
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
}

// fixDetection puts right what checkDetection looks at, and says what it did.
func fixDetection() []string {
	if _, err := winsec.EnsureFileSystemAudit(); err == nil {
		return []string{"file auditing is on"}
	}
	return nil
}

// syncTools are sync and backup programs (process name, lowercase -> product):
// software that legitimately reads the files in your folders.
var syncTools = map[string]string{
	"onedrive.exe": "OneDrive", "dropbox.exe": "Dropbox", "googledrivefs.exe": "Google Drive",
	"icloudckks.exe": "iCloud", "bztransmit.exe": "Backblaze", "bztransmit64.exe": "Backblaze",
	"crashplanservice.exe": "CrashPlan", "reflectbin.exe": "Macrium Reflect", "veeam.endpoint.service.exe": "Veeam",
	"syncthing.exe": "Syncthing", "megasync.exe": "MEGA", "everything.exe": "",
}

// What the baits check says about the tripwire on each file.
const (
	lostTripwire = "%d file(s) lost their audit rule"
	verifyHint   = "; run as admin to verify audit rules"
)

// recentFolder is where the desktop keeps shortcuts to files you opened.
func recentFolder(u config.UserInfo) string {
	return filepath.Join(u.RoamingAppData, `Microsoft\Windows\Recent`)
}
