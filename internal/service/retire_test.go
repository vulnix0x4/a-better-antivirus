package service

import (
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// A decoy waits for its real app to close before it's retired: found by the
// program's name, whatever its case.
func TestAnyNamed(t *testing.T) {
	snap := map[uint32]procinfo.Entry{1: {PID: 1, Exe: "Brave.exe"}, 2: {PID: 2, Exe: "explorer.exe"}}
	if !anyNamed(snap, []string{"brave.exe"}) {
		t.Error("Brave runs")
	}
	if anyNamed(snap, []string{"vivaldi.exe"}) || anyNamed(snap, nil) {
		t.Error("Vivaldi doesn't")
	}
}
