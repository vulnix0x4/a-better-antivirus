// Package respond undoes or finishes responses: release isolation, resume or
// kill frozen processes, unblock programs. Used by the elevated CLI.
package respond

import (
	"fmt"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
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
		if err := procinfo.Resume(f.PID); err != nil {
			rep.bad("resume pid %d: %v", f.PID, err)
			keep = append(keep, f)
		} else {
			rep.ok("resumed %s (pid %d)", procinfo.BaseName(f.Image), f.PID)
		}
	}
	return keep
}

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

// Kill terminates the processes frozen for an alert. The program stays blocked.
func Kill(alertID string) (*Report, error) {
	rep := &Report{}
	a, err := alerts.Load(alertID)
	if err != nil {
		return rep, err
	}
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
	if len(rep.Lines) == 0 && len(rep.Errors) == 0 {
		rep.ok("nothing frozen for this alert (already exited or released)")
	}
	alerts.Update(a.ID, func(x *alerts.Alert) {
		x.AddAction(config.ActionKill, nil, "by you")
		x.Status, x.Note = "resolved", "killed"
	})
	return rep, err
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
	alerts.Update(a.ID, func(x *alerts.Alert) { x.Status, x.Note = "resolved", "you said it was yours" })
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
