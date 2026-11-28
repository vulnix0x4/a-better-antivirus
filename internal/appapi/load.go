package appapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/minertrap"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/update"
)

// maxAlerts is how many alerts the app reads (newest first): History's
// twelve weeks, many times over.
const maxAlerts = 500

// Load reads everything the screens are built from (administrators only:
// the data folder is closed to everyone else). version is the app's.
func Load(version string) (*Source, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}
	st, err := config.LoadState()
	if err != nil {
		return nil, err
	}
	list, err := alerts.List(maxAlerts)
	if err != nil {
		return nil, err
	}
	s := &Source{Version: version, Now: time.Now(), Config: cfg, State: st, Alerts: list,
		ClipboardSupported: runtime.GOOS == "windows", MinersSupported: minertrap.Supported(),
		Updatable: update.Updatable(version), Newer: update.Newer}
	if svc, err := svcctl.Status(); err == nil && svc == svcctl.Running {
		s.ServiceRunning = true
	}
	if sec, err := config.LoadSecrets(); err == nil && sec.Phone.Enabled() {
		s.PhoneVia = sec.Phone.Kind
	}
	if st.ServiceVersion != "" && version == "dev" {
		s.Version = st.ServiceVersion
	}
	return s, nil
}

// LoadAlert reads one alert by its exact ID (no prefixes: the page passes
// IDs it was given).
func LoadAlert(id string) (*alerts.Alert, error) {
	if !ValidAlertID(id) {
		return nil, fmt.Errorf("not an alert: %q", id)
	}
	if !AlertExists(id) {
		return nil, fmt.Errorf("no alert %s", id)
	}
	return alerts.Load(id)
}

// AlertExists reports whether alert id has a file (exactly that name).
func AlertExists(id string) bool {
	if !ValidAlertID(id) {
		return false
	}
	fi, err := os.Lstat(filepath.Join(paths.AlertsDir(), id+".json"))
	return err == nil && fi.Mode().IsRegular()
}

// BaitExists reports whether bait id is planted.
func BaitExists(id string) bool {
	if !ValidBaitID(id) {
		return false
	}
	st, err := config.LoadState()
	if err != nil {
		return false
	}
	b := st.Baits[id]
	return b != nil && b.Status != "retired"
}

// DiskExists checks IDs against the files on disk.
var DiskExists = Exists{Alert: AlertExists, Bait: BaitExists}

// LoadLocked builds the locked view from the status file anyone may read.
func LoadLocked(version, alertID string) *Locked {
	p, err := config.LoadPublic()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		p = nil
	}
	if !ValidAlertID(alertID) {
		alertID = ""
	}
	return LockedView(p, version, alertID, time.Now())
}
