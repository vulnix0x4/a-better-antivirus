package ui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// The list line for the browser you're using, left running and cut off:
// every item says something (it used to show "internet cut ·   · ✓ …").
func TestAlertListHasNoEmptyItem(t *testing.T) {
	a := &alerts.Alert{ID: "20261124-101500-cd34", Time: time.Now(), Kind: alerts.KindRead, Tier: config.TierCritical, Status: "resolved",
		Note: "you gave Chrome its internet back (nothing trusted)", Title: "Something inside your Chrome read a bait: its internet is cut",
		Baits:   []alerts.BaitHit{{Name: "extra profile inside your Chrome", Access: "read", Time: time.Now()}},
		Process: &alerts.Process{PID: 5532, Image: `C:\Program Files\Google\Chrome\Application\chrome.exe`}}
	a.AddAction(config.ActionBlockProgram, nil, `C:\Program Files\Google\Chrome\Application\chrome.exe`)
	a.AddAction(config.ActionLeftRunning, nil, "it's the Chrome you're using")
	a.AddAction(config.Action("something-new"), nil, "")
	got := AlertTable([]*alerts.Alert{a}, 120)
	plain := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(got, "")
	if regexp.MustCompile(`·\s+·`).MatchString(plain) {
		t.Fatalf("an empty item:\n%s", plain)
	}
	if !strings.Contains(plain, "internet cut · left running") {
		t.Fatalf("list line:\n%s", plain)
	}
}

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
