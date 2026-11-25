package engine

import (
	"os"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Edge reads the password list on the Desktop by itself after every start.
// ABA rates that "looks legitimate" (info): it's noted, in the history, but
// nobody is interrupted for it, the first time or any time after.
func TestLegitimateReadIsNotedQuietly(t *testing.T) {
	e, f := setup("balanced")
	f.images[3000] = edgeExe
	signed(f, edgeExe, "Microsoft Corporation")
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierInfo || a.Status != alerts.StatusNoted || len(a.Actions) != 0 {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.desktop) != 0 || len(f.phone) != 0 {
		t.Fatalf("popups %v, phone %v", f.desktop, f.phone)
	}
	// Later, as a new process (Edge started again), the same: still quiet.
	f.images[3100] = edgeExe
	e.HandleAccess(ev(3100, edgeExe, desktopBait, 1))
	if len(f.saved) != 2 || len(f.desktop) != 0 || len(f.phone) != 0 {
		t.Fatalf("again: alerts %d, popups %v, phone %v", len(f.saved), f.desktop, f.phone)
	}
	// Someone who asked for every alert on their phone still gets it there.
	e.cfg.PhoneMinTier = config.TierInfo
	f.images[3200] = edgeExe
	e.HandleAccess(ev(3200, edgeExe, desktopBait, 1))
	if len(f.desktop) != 0 || len(f.phone) != 1 {
		t.Fatalf("\"Everything\" on the phone: popups %v, phone %v", f.desktop, f.phone)
	}
}

// Noted quietly as a read; it goes on to change or delete the bait: that you
// hear about.
func TestQuietReadThatTurnsDestructiveIsTold(t *testing.T) {
	e, f := setup("balanced")
	f.images[3000] = edgeExe
	signed(f, edgeExe, "Microsoft Corporation")
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 0x10000)) // delete
	if len(f.desktop) != 1 {
		t.Fatalf("a delete after a quiet read: popups %v", f.desktop)
	}
	for _, a := range f.saved {
		if a.Kind == alerts.KindDelete && a.Status != "open" {
			t.Fatalf("the delete's alert waits for no answer: %+v", a)
		}
	}

	// The same, caught inside its open (claimed): the event log says it
	// went on to delete it.
	e, f = setup("balanced")
	f.images[3000] = edgeExe
	signed(f, edgeExe, "Microsoft Corporation")
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	e.claim(3000)
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 0x10000))
	a := only(f)
	if len(f.desktop) != 1 || a.Kind != alerts.KindDelete || a.Status != "open" {
		t.Fatalf("noted, then the delete: popups %v, alert %+v", f.desktop, a)
	}
}

// Everything else is told as before: suspicious, critical, a decoy being
// retired, a test.
func TestOnlyLegitimateReadsAreQuiet(t *testing.T) {
	// Suspicious: a signed app in your own folders.
	e, f := setup("balanced")
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.sigs[code] = provenance.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	e.HandleAccess(ev(200, code, desktopBait, 1))
	if a := only(f); a == nil || a.Tier != config.TierWarn || a.Status != "open" || len(f.desktop) != 1 || len(f.phone) != 1 {
		t.Fatalf("warn: %+v popups %v phone %v", a, f.desktop, f.phone)
	}
	// Critical.
	e, f = setup("balanced")
	e.HandleAccess(ev(100, `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`, desktopBait, 1))
	if len(f.desktop) != 1 || len(f.phone) != 1 {
		t.Fatalf("critical: popups %v phone %v", f.desktop, f.phone)
	}
	// A decoy being retired (the real app reading its own data).
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	localState := e.cfg.User.LocalAppData + `\Google\Chrome\User Data\Local State`
	if err := os.WriteFile(localState, []byte(`{"profile":{"info_cache":{"Default":{},"Profile 23":{"name":"Work"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	if a := only(f); a == nil || a.Kind != alerts.KindDecoyRetired || len(f.desktop) != 1 {
		t.Fatalf("decoy retired: %+v popups %v", a, f.desktop)
	}
	// `aba test`.
	e, f = setup("balanced")
	f.test = &TestRequest{PID: 100}
	e.HandleAccess(ev(100, `C:\Users\bob\AppData\Local\Temp\aba-test-1.exe`, desktopBait, 1))
	if len(f.desktop) != 1 {
		t.Fatalf("test: popups %v", f.desktop)
	}
}
