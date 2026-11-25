package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// A read noted quietly is in the list, calmly, and its detail still offers
// to trust it.
func TestNotedAlertIsCalm(t *testing.T) {
	a := &alerts.Alert{ID: "20261124-101500-ab12", Time: time.Now(), Kind: alerts.KindRead, Tier: config.TierInfo, Status: alerts.StatusNoted,
		Title: "msedge.exe read a bait (looks legitimate)", Baits: []alerts.BaitHit{{Name: "passwords.txt on the Desktop", Access: "read", Time: time.Now()}},
		Process: &alerts.Process{PID: 3000, Image: `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, Signature: provenance.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}}}
	if got := AlertTable([]*alerts.Alert{a}, 100); !strings.Contains(got, "noted quietly") {
		t.Fatalf("list:\n%s", got)
	}
	got := AlertDetail(a)
	for _, want := range []string{"Noted quietly", "aba trust ab12"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "If you didn't cause this") {
		t.Error("no checklist for a read that looks legitimate")
	}
}
