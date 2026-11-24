// Package respond undoes or finishes responses: release isolation, resume or
// kill frozen processes, unblock programs. Used by the elevated CLI.
package respond

import (
	"fmt"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// Report lists what was done.
type Report struct {
	Lines  []string
	Errors []string
}

func (r *Report) ok(f string, a ...any)  { r.Lines = append(r.Lines, fmt.Sprintf(f, a...)) }
func (r *Report) bad(f string, a ...any) { r.Errors = append(r.Errors, fmt.Sprintf(f, a...)) }

// Release restores the network and resumes/unblocks everything (alertID ""),
// or only what belongs to one alert.
func Release(alertID string) (*Report, error) {
	rep := &Report{}

	// 1. Network first, without the state lock. Getting the user back online
	// must never depend on the service being responsive: if it's busy or
	// stuck holding the lock, isolation would otherwise stay in place.
	snap, _ := config.LoadState() // lock-free read (writes are atomic renames)
	ours := alertID == "" || (snap != nil && snap.Isolation != nil && snap.Isolation.AlertID == alertID)
	if ours {
		if err := netguard.Unisolate(); err != nil {
			rep.bad("remove isolation: %v", err)
		} else if snap == nil || snap.Isolation != nil || alertID == "" {
			rep.ok("network isolation removed")
		}
		if snap != nil && len(snap.DisabledAdapters) > 0 {
			if err := netguard.EnableAdapters(snap.DisabledAdapters); err != nil {
				rep.bad("re-enable adapters: %v", err)
			} else {
				rep.ok("re-enabled adapters: %s", strings.Join(snap.DisabledAdapters, ", "))
			}
		}
	}

	// 2. Unfreeze and unblock, and record it all, under the lock.
	err := config.UpdateState(func(st *config.State) error {
		if ours {
			st.Isolation = nil
			st.DisabledAdapters = nil
		}
		st.Frozen = resumeWhere(st.Frozen, alertID, rep)
		st.Blocked = unblockWhere(st.Blocked, alertID, rep)
		return nil
	})
	if err != nil {
		// Still undo what we can without the bookkeeping.
		if snap != nil {
			resumeWhere(snap.Frozen, alertID, rep)
			unblockWhere(snap.Blocked, alertID, rep)
		}
		rep.bad("couldn't update ABA's records (%v); the network was restored anyway", err)
		return rep, nil
	}
	released()
	markResolved(alertID, "released")
	return rep, nil
}

func resumeWhere(frozen []config.FrozenProcess, alertID string, rep *Report) []config.FrozenProcess {
	var keep []config.FrozenProcess
	for _, f := range frozen {
		if alertID != "" && f.AlertID != alertID {
			keep = append(keep, f)
			continue
		}
		if !procinfo.Alive(f.PID, f.CreateTime) {
			continue
		}
		// (It's also held frozen by the service, see procinfo.Hold: that part
		// is let go once it's off the record. See released.)
		if err := procinfo.Resume(f.PID); err != nil {
			rep.bad("resume pid %d: %v", f.PID, err)
			keep = append(keep, f)
		} else {
			rep.ok("resumed %s (pid %d)", procinfo.BaseName(f.Image), f.PID)
		}
	}
	return keep
}

// released tells the service that frozen processes were just taken off the
// record, so that it lets go of its holds on them: only then do the ones
// that were resumed actually run again. (No service, no holds.)
func released() { svcctl.Send(svcctl.Released) }

func unblockWhere(blocked []config.BlockedProgram, alertID string, rep *Report) []config.BlockedProgram {
	var keep []config.BlockedProgram
	for _, b := range blocked {
		if alertID != "" && b.AlertID != alertID {
			keep = append(keep, b)
			continue
		}
		if err := netguard.UnblockProgram(b.Path); err != nil {
			rep.bad("unblock %s: %v", b.Path, err)
			keep = append(keep, b)
		} else {
			rep.ok("internet restored for %s", b.Path)
		}
	}
	return keep
}

// Kill terminates the processes frozen for an alert. The program stays
// blocked. The evidence is saved first (see Preserve).
func Kill(alertID string) (*Report, error) {
	rep := &Report{}
	a, err := alerts.Load(alertID)
	if err != nil {
		return rep, err
	}
	Preserve(a, rep)
	err = config.UpdateState(func(st *config.State) error {
		var keep []config.FrozenProcess
		for _, f := range st.Frozen {
			if f.AlertID != a.ID {
				keep = append(keep, f)
				continue
			}
			if !procinfo.Alive(f.PID, f.CreateTime) {
				continue
			}
			if err := procinfo.Kill(f.PID); err != nil {
				rep.bad("kill pid %d: %v", f.PID, err)
				keep = append(keep, f)
			} else {
				rep.ok("killed %s (pid %d)", procinfo.BaseName(f.Image), f.PID)
			}
		}
		st.Frozen = keep
		return nil
	})
	released()
	if len(rep.Lines) == 0 && len(rep.Errors) == 0 {
		rep.ok("nothing frozen for this alert (already exited or released)")
	}
	alerts.Update(a.ID, func(x *alerts.Alert) {
		x.AddAction(config.ActionKill, nil, "by you")
		x.Status, x.Note = "resolved", "killed"
	})
	return rep, err
}

// Preserve makes sure the evidence about an alert's frozen program is saved
// before it's ended: what the autopsy found, a copy of the program, what it
// staged, its memory (see package autopsy). The service saves it a moment
// after the catch; if it's still at it, this waits for it; if it never did
// (an alert from an older version, or the service wasn't running), the
// evidence is saved here, without the flight recorder's part.
func Preserve(a *alerts.Alert, rep *Report) {
	st, _ := config.LoadState()
	alive := false
	if st != nil {
		for _, f := range st.Frozen {
			alive = alive || (f.AlertID == a.ID && procinfo.Alive(f.PID, f.CreateTime))
		}
	}
	if !alive {
		return
	}
	done := func(x *alerts.Alert) bool {
		return x.Autopsy != nil && !x.Autopsy.Finished.IsZero() && x.Autopsy.Evidence != ""
	}
	if done(a) {
		return
	}
	if time.Since(a.Time) < 3*time.Minute || (a.Autopsy != nil && a.Autopsy.Finished.IsZero()) {
		if x, err := autopsy.Wait(a.ID, 90*time.Second, alerts.Load); err == nil && done(x) {
			rep.ok("evidence saved to %s", x.Autopsy.Evidence)
			return
		}
	}
	cfg, _ := config.LoadConfig()
	c, err := autopsy.CaseFrom(a, cfg, st)
	if err != nil {
		return
	}
	ap := autopsy.Run(c, autopsy.SystemHooks(cfg == nil || !cfg.NoMemoryImage))
	alerts.Update(a.ID, func(x *alerts.Alert) {
		if x.Autopsy == nil || x.Autopsy.Finished.IsZero() {
			x.Autopsy = ap
			return
		}
		x.Autopsy.Evidence, x.Autopsy.MemoryImage = ap.Evidence, ap.MemoryImage // keep the service's findings
	})
	if ap.Evidence != "" {
		rep.ok("evidence saved to %s", ap.Evidence)
	}
}

// Resume declares an alert a false positive: unfreeze and unblock its program.
func Resume(alertID string) (*Report, error) {
	a, err := alerts.Load(alertID)
	if err != nil {
		return &Report{}, err
	}
	rep := &Report{}
	err = config.UpdateState(func(st *config.State) error {
		st.Frozen = resumeWhere(st.Frozen, a.ID, rep)
		st.Blocked = unblockWhere(st.Blocked, a.ID, rep)
		return nil
	})
	released()
	// `aba resume` is "not sure: let it run again, without trusting it", and
	// the popup's "It's mine: unfreeze it (this time only)" runs it too.
	note := "let run again by you (nothing trusted)"
	if a.Verdict.KeepRunning {
		note = "you gave " + alerts.BrowserName(a.ExeName()) + " its internet back (nothing trusted)"
	}
	alerts.Update(a.ID, func(x *alerts.Alert) { x.Status, x.Note = "resolved", note })
	return rep, err
}

func markResolved(alertID, note string) {
	if alertID != "" {
		alerts.Update(alertID, func(a *alerts.Alert) { a.Status, a.Note = "resolved", note })
		return
	}
	list, _ := alerts.List(200)
	for _, a := range list {
		if a.Status == "open" && (a.Did(config.ActionFreeze) || a.Did(config.ActionIsolate) || a.Did(config.ActionBlockProgram) || a.Did(config.ActionDisableAdapters)) {
			alerts.Update(a.ID, func(x *alerts.Alert) { x.Status, x.Note = "resolved", note })
		}
	}
}
