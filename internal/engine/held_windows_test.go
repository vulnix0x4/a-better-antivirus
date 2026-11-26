package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/instant"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// CI, right after a service restart: find.exe read the Desktop passwords,
// then Discord's data, then went for the fake Brave's `Local State`. It was
// a known sweeper by then, so the instant path decided about it while it was
// still paused inside that open, the bait's oplock held. Deciding asked
// whether a real Brave had taken ABA's fake profile inside it as its own,
// which meant reading Brave's `Local State`: the very bait being held. ABA's
// read waited for the oplock, the oplock for the decision. find.exe stayed
// paused for good, the bait went unguarded, and no sweep was ever reported.
func TestSweepDecidedWhileTheBaitIsHeld(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	local := filepath.Join(t.TempDir(), "AppData", "Local")
	ud := filepath.Join(local, `BraveSoftware\Brave-Browser\User Data`)
	if err := os.MkdirAll(ud, 0o755); err != nil {
		t.Fatal(err)
	}
	braveLS := filepath.Join(ud, "Local State")
	if err := os.WriteFile(braveLS, []byte(`{"profile":{"info_cache":{"Default":{}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cfg.User.LocalAppData = local
	st := stateWithAll()
	st.Baits["brave"] = &config.BaitState{ID: "brave", Name: "Brave browser profile",
		Files: []config.BaitFile{{Path: braveLS, Audit: true}}}
	e.Configure(e.cfg, st)

	find := `C:\Windows\System32\find.exe`
	f.images[300] = find
	f.sigs[find] = provenance.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}
	if e.DecideInstant(300, desktopBait) || e.DecideInstant(300, discordBait) {
		t.Fatal("a Windows program reading one or two apps' data is only a warning")
	}
	if got := e.SweepSuspect(braveLS, []uint32{300}); got != 300 {
		t.Fatalf("find.exe has read two apps' data: the suspect, got %d", got)
	}

	// The guard on the bait: ABA's own open of it now waits until it's let go.
	g, err := instant.Arm(braveLS)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		ok  bool
		why string
	}
	done := make(chan result, 1)
	go func() {
		ok, why := e.DecideInstantWhy(300, braveLS)
		done <- result{ok, why}
	}()
	var r result
	select {
	case r = <-done:
		g.Release()
	case <-time.After(5 * time.Second):
		g.Release()
		<-done
		t.Fatal("deciding about a program paused in a held bait hung: it opened the held bait itself")
	}
	if !r.ok {
		t.Fatalf("a third app's data: frozen inside the open, got %s", r.why)
	}
}
