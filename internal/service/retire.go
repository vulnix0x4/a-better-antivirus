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
