package config

import (
	"encoding/json"
	"os"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// What ABA knows is worth more to a stealer than to anyone else: state.json
// lists every bait, config.json says which programs you trusted with which
// bait, the alerts and the log name baits too. Anything running as you could
// once read all of it, and simply walk around every tripwire.
//
// So the data folder is for SYSTEM and administrators only, and the little
// that's safe to show without admin rights (is it running, is it healthy, is
// something frozen) goes in a separate file anyone may read: Public.

// Public is what the dashboard shows without admin rights. No paths, no bait
// names, no program names, no alert contents. And not how ABA is set to
// respond: "alerts only" or "still learning" tells a stealer it can read
// what it likes and will only be reported, not stopped.
type Public struct {
	Version       string        `json:"version"`
	Heartbeat     time.Time     `json:"heartbeat"`
	Health        []HealthItem  `json:"health,omitempty"`
	Baits         int           `json:"baits"`        // active
	BaitsHealthy  int           `json:"baitsHealthy"` // of those, healthy
	AutoUpdate    bool          `json:"autoUpdate"`
	Update        *UpdateStatus `json:"update,omitempty"`
	IsolatedSince *time.Time    `json:"isolatedSince,omitempty"`
	Frozen        int           `json:"frozen"`
	Blocked       int           `json:"blocked"`
	Alerts        int           `json:"alerts"`     // in history
	OpenAlerts    int           `json:"openAlerts"` // not yet answered
}

// MakePublic boils config and state down to what's safe to show.
func MakePublic(cfg *Config, st *State, version string, alerts, open int) *Public {
	p := &Public{Version: version, AutoUpdate: cfg.AutoUpdate, Alerts: alerts, OpenAlerts: open}
	if st == nil {
		return p
	}
	p.Heartbeat, p.Health, p.Update = st.Heartbeat, st.Health, st.Update
	p.Frozen, p.Blocked = len(st.Frozen), len(st.Blocked)
	if st.Isolation != nil {
		since := st.Isolation.Since
		p.IsolatedSince = &since
	}
	for _, b := range st.Baits {
		if b.Status == "retired" {
			continue
		}
		p.Baits++
		if b.Status == "ok" {
			p.BaitsHealthy++
		}
	}
	return p
}

// View turns Public back into the shapes the dashboard draws from. Counts
// survive; everything that was left out stays out (entries are blank).
func (p *Public) View() (*Config, *State) {
	cfg := &Config{AutoUpdate: p.AutoUpdate, Responses: map[Tier][]Action{}}
	st := NewState()
	st.Heartbeat, st.Health, st.Update, st.ServiceVersion = p.Heartbeat, p.Health, p.Update, p.Version
	st.Frozen = make([]FrozenProcess, p.Frozen)
	st.Blocked = make([]BlockedProgram, p.Blocked)
	if p.IsolatedSince != nil {
		st.Isolation = &Isolation{Since: *p.IsolatedSince}
	}
	for i := 0; i < p.Baits; i++ {
		status := "ok"
		if i >= p.BaitsHealthy {
			status = "error"
		}
		st.Baits[string(rune('a'+i%26))+string(rune('0'+i/26))] = &BaitState{Status: status}
	}
	return cfg, st
}

func SavePublic(p *Public) error { return writeJSONAtomic(paths.PublicStatusFile(), p) }

func LoadPublic() (*Public, error) {
	b, err := os.ReadFile(paths.PublicStatusFile())
	if err != nil {
		return nil, err
	}
	p := &Public{}
	return p, json.Unmarshal(b, p)
}

// LockDataDir creates the data folder if need be and restricts it (see
// above). Installs made by older versions, where Users could read all of it,
// are tightened the first time the new service starts.
func LockDataDir() error {
	if err := os.MkdirAll(paths.AlertsDir(), 0o755); err != nil {
		return err
	}
	return lockDir(paths.DataDir(), paths.PublicDir())
}
