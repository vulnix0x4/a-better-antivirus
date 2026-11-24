package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// The event log reports bait reads in UTC; the alert shows them in the same
// local time as its header.
func TestAlertTimesAreLocal(t *testing.T) {
	at := time.Date(2026, 11, 23, 5, 29, 9, 898e6, time.UTC)
	a := &alerts.Alert{ID: "20261123-052909-ab12", Time: at, Kind: alerts.KindRead, Tier: config.TierWarn, Title: "x read a bait",
		Baits: []alerts.BaitHit{{Name: "a bait", Path: `C:\x`, Access: "read", Time: at}}}
	got := AlertDetail(a)
	want := at.Local().Format("15:04:05.000")
	if !strings.Contains(got, want) || !strings.Contains(got, at.Local().Format("Mon Jan 2 2006, 15:04:05")) {
		t.Fatalf("want local %s in:\n%s", want, got)
	}
}
