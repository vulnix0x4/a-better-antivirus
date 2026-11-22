package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
)

func swap(pid uint32, image string) *detect.Access {
	return &detect.Access{PID: pid, Image: image, Op: detect.OpSwap, Time: time.Now(), Swap: &detect.Swap{
		Coin: "bitcoin", Bait: "1FakeBaitAddressxxxxxxxxxxxxxxxxx", Replacement: "1AttackerAddressyyyyyyyyyyyyyyyyy",
		How: "it took over the clipboard to swap the address", LatencyMS: 4}}
}

func TestClipperIsCaught(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Roaming\svc\update.exe`
	e.HandleAccess(swap(500, img))
	a := only(f)
	if a == nil {
		t.Fatal("no alert for a clipper")
	}
	if a.Kind != alerts.KindClipper || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("want a critical clipper alert that froze and blocked it: %+v", a)
	}
	if !strings.HasPrefix(a.Title, "Clipper caught: update.exe") {
		t.Errorf("title: %q", a.Title)
	}
	if len(a.Baits) != 1 || a.Baits[0].ID != ClipboardBait || a.Baits[0].Access != "swap" {
		t.Errorf("bait hit: %+v", a.Baits)
	}
	if !strings.Contains(strings.Join(a.Verdict.Reasons, " | "), "1AttackerAddressyyyyyyyyyyyyyyyyy") {
		t.Errorf("the attacker's address should be in the alert: %v", a.Verdict.Reasons)
	}
	if len(f.phone) != 1 || len(f.desktop) != 1 {
		t.Errorf("notified: phone %v desktop %v", f.phone, f.desktop)
	}
}

// No signature and no rule makes swapping a wallet address acceptable.
func TestClipperSignedAndTrustedIsStillCaught(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe` // where injected clippers like to live
	signed(f, img, "Microsoft Corporation")
	e.cfg.Ignore = []config.IgnoreRule{{Path: img}}
	e.Configure(e.cfg, stateWithAll())
	e.HandleAccess(swap(501, img))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) {
		t.Fatalf("want it frozen whatever signed it, rule or not: %+v", a)
	}
}

// A program that only looked harmless before (it read a bait the way an app
// might) gets a new, critical alert when it swaps an address.
func TestClipperAfterWarnGetsItsOwnAlert(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Program Files\Some App\app.exe`
	signed(f, img, "Some App Ltd")
	e.HandleAccess(ev(502, img, desktopBait, 1))
	first := only(f)
	if first == nil || first.Tier == config.TierCritical {
		t.Fatalf("setup: want a non-critical first alert, got %+v", first)
	}
	e.HandleAccess(swap(502, img))
	if len(f.saved) != 2 {
		t.Fatalf("want a second alert for the swap, have %d", len(f.saved))
	}
	for _, a := range f.saved {
		if a.ID != first.ID && (a.Kind != alerts.KindClipper || a.Tier != config.TierCritical) {
			t.Fatalf("second alert: %+v", a)
		}
	}
}

func TestSwapWithoutDetailsIsIgnored(t *testing.T) {
	e, f := setup("balanced")
	e.HandleAccess(&detect.Access{PID: 503, Image: `C:\x.exe`, Op: detect.OpSwap, Time: time.Now()})
	if len(f.saved) != 0 {
		t.Fatalf("a swap report without what was swapped raised an alert")
	}
}
