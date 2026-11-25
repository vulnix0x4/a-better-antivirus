package service

import (
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// specOf is the spec of bait id under cfg (which may be nil).
func specOf(cfg *config.Config, id string) (baits.Spec, bool) {
	if cfg == nil {
		return baits.ByID(id)
	}
	return baits.SpecByID(cfg, id)
}

// appRunning reports whether a program named like spec's genuine app is
// running. It's only ever a reason to wait before retiring the decoy (the
// real app may have its files open), never one to trust anything, so the
// name is enough.
func appRunning(spec baits.Spec) bool {
	if len(spec.OwnerExes) == 0 {
		return false
	}
	snap, err := procinfo.Snapshot()
	if err != nil {
		return false
	}
	return anyNamed(snap, spec.OwnerExes)
}

// retiringFor reports whether path belongs to a decoy waiting to be retired
// once its real app has closed (see RetireDecoy), and every one of pids is
// that app (by program name: they hold the file, nothing is let through).
func (s *server) retiringFor(path string, pids []uint32) bool {
	id, ok := s.eng.IsBait(path)
	if !ok {
		return false
	}
	s.mu.Lock()
	_, waiting := s.retireLater[id]
	cfg := s.cfg
	s.mu.Unlock()
	spec, ok := specOf(cfg, id)
	if !waiting || !ok || len(pids) == 0 {
		return false
	}
	for _, pid := range pids {
		img, err := procinfo.ImagePath(pid)
		if err != nil || !anyNamed(map[uint32]procinfo.Entry{pid: {PID: pid, Exe: img}}, spec.OwnerExes) {
			return false
		}
	}
	return true
}

// anyNamed reports whether a process in snap runs a program called one of
// names (lowercase file names).
func anyNamed(snap map[uint32]procinfo.Entry, names []string) bool {
	for _, p := range snap {
		exe := strings.ToLower(procinfo.BaseName(p.Exe))
		for _, n := range names {
			if exe == n {
				return true
			}
		}
	}
	return false
}
