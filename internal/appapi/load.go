package appapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// The app stays clear of the packages that freeze, cut off and update
// (package update brings install, respond and the firewall code with it):
// what does those things is the CLI. So the two version checks are here,
// the same as update.Newer and update.Updatable (a test keeps them so).

// Newer reports whether release tag is newer than version current (only
// plain vX.Y.Z versions compare).
func Newer(current, tag string) bool {
	c, ok1 := parseVersion(current)
	t, ok2 := parseVersion(tag)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if t[i] != c[i] {
			return t[i] > c[i]
		}
	}
	return false
}

// Updatable reports whether a build of version v updates itself.
func Updatable(v string) bool { _, ok := parseVersion(v); return ok }

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

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
		ClipboardSupported: runtime.GOOS == "windows", MinersSupported: runtime.GOOS == "windows",
		Updatable: Updatable(version), Newer: Newer}
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
