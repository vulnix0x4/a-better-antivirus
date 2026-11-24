package autopsy

import (
	"errors"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// SystemHooks are the autopsy's hooks into this operating system, without
// the flight recorder (which only the service has).
func SystemHooks(memoryImage bool) Hooks {
	return Hooks{
		StartedAt:   procinfo.StartedAt,
		OpenFiles:   procinfo.OpenFiles,
		ReadMemory:  procinfo.ReadMemory,
		WorkingDir:  procinfo.WorkingDir,
		StagingDirs: DefaultStagingDirs,
		EvidenceDir: paths.EvidenceDir(),
		MemoryImage: memoryImage,
	}
}

// CaseFrom rebuilds an autopsy's Case from a saved alert (for an autopsy the
// CLI runs itself: `aba autopsy --now`, or `aba kill` saving the evidence).
func CaseFrom(a *alerts.Alert, cfg *config.Config, st *config.State) (Case, error) {
	if a.Process == nil || a.Process.PID == 0 {
		return Case{}, errors.New("this alert isn't about a program")
	}
	c := Case{AlertID: a.ID, Test: a.Test, PID: a.Process.PID, Image: a.Process.Image, Tree: a.Process.TreePIDs, Conns: a.Process.Connections,
		BaitFiles: map[string]string{}}
	if len(a.Baits) > 0 {
		c.BaitAt = a.Baits[0].Time
	}
	if c.BaitAt.IsZero() {
		c.BaitAt = a.Time
	}
	for _, r := range a.Verdict.Reasons {
		if w, ok := strings.CutPrefix(r, "the address it swapped in (the attacker's): "); ok {
			c.Wallet = w
		}
	}
	planted := map[string]bool{}
	if st != nil {
		for _, f := range st.Frozen {
			if f.AlertID == a.ID && procinfo.Alive(f.PID, f.CreateTime) {
				c.Frozen = append(c.Frozen, f.PID)
			}
		}
		for id, bs := range st.Baits {
			if bs.Status != "retired" {
				planted[id] = true
			}
			for _, f := range bs.Files {
				c.BaitFiles[f.Path] = bs.Name
			}
		}
	}
	if cfg != nil {
		c.User = cfg.User
		c.Stores = baits.RealStores(cfg.User, planted)
	}
	return c, nil
}

// Wait waits (at most for d) for the service to finish the autopsy of the
// alert with the given ID, and returns the alert as it is then.
func Wait(id string, d time.Duration, load func(string) (*alerts.Alert, error)) (*alerts.Alert, error) {
	deadline := time.Now().Add(d)
	for {
		a, err := load(id)
		if err != nil {
			return nil, err
		}
		if (a.Autopsy != nil && !a.Autopsy.Finished.IsZero()) || time.Now().After(deadline) {
			return a, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
}
