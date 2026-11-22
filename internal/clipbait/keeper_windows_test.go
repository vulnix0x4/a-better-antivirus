package clipbait

import (
	"errors"
	"os"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

// keeperGuard is a Guard that saves and puts back the clipboard through the
// keeper, a copy of this test binary in the private window station (as ABA
// does, but as this account rather than the person's: tests aren't SYSTEM).
func keeperGuard(t *testing.T) *Guard {
	t.Helper()
	exe, _ := os.Executable()
	var started int
	g := newGuard(t, &Guard{AsUser: func(args ...string) (*session.Helper, error) {
		started++
		return session.StartOn(testDeskPath, exe, args...)
	}})
	t.Cleanup(func() {
		if started == 0 {
			t.Error("the keeper was never used")
		}
	})
	return g
}

func TestKeeperPutsBackWhatWasCopied(t *testing.T) {
	g := keeperGuard(t)
	// What a browser leaves, plus OLE's bookkeeping (the new Notepad's).
	g.put(t, "notes from yesterday", "HTML Format", "DataObject", "Ole Private Data")
	f, err := g.Cycle(Bitcoin)
	if err != nil || f != nil {
		t.Fatalf("Cycle = %+v, %v; want a bait out and nothing found", f, err)
	}
	s := g.get()
	if s.text != "notes from yesterday" || !s.has("HTML Format") {
		t.Fatalf("clipboard not put back: %+v", s)
	}
	if s.has("DataObject") || s.has("Ole Private Data") {
		t.Errorf("OLE's bookkeeping should be left out: %v", s.formats)
	}
	if !s.has(flagNoHistory) || !s.has(flagNoCloud) {
		t.Errorf("the copy put back should be kept out of clipboard history: %v", s.formats)
	}
}

func TestKeeperCatchAndPutBack(t *testing.T) {
	g := keeperGuard(t)
	cs := start(t, "reader", "nowindow")
	g.Candidates = pids(cs)
	g.put(t, "a shopping list", "HTML Format")
	f, err := g.Cycle(Ethereum)
	if err != nil || f == nil {
		t.Fatalf("Cycle = %+v, %v; want a finding", f, err)
	}
	if f.PID != cs[1].pid {
		t.Fatalf("blamed pid %d, want the clipper (pid %d)", f.PID, cs[1].pid)
	}
	g.Finish()
	if s := g.get(); s.text != "a shopping list" || !s.has("HTML Format") {
		t.Fatalf("clipboard not put back after the catch: %+v", s)
	}
}

func TestKeeperLeavesSomethingElseAlone(t *testing.T) {
	g := keeperGuard(t)
	g.put(t, "a photo", "Some Private App Format")
	_, err := g.Cycle(Bitcoin)
	var skip Skipped
	if !errors.As(err, &skip) {
		t.Fatalf("Cycle = %v; want it skipped", err)
	}
	if s := g.get(); s.text != "a photo" || !s.has("Some Private App Format") {
		t.Fatalf("clipboard changed: %+v", s)
	}
}
