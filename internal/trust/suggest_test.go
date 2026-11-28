package trust

import (
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

func TestSuggest(t *testing.T) {
	signed := provenance.Result{Signed: true, Valid: true, Signer: "Backblaze"}
	mk := func(id string, at time.Time, bait string, tier config.Tier) *alerts.Alert {
		return &alerts.Alert{ID: id, Time: at, Kind: alerts.KindRead, Tier: tier,
			Baits:   []alerts.BaitHit{{ID: bait}},
			Process: &alerts.Process{Image: "/opt/backblaze/bztransmit", Signature: signed}}
	}
	t0 := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	list := []*alerts.Alert{
		mk("3", t0.Add(2*time.Hour), "aws", config.TierWarn),
		mk("2", t0.Add(time.Hour), "discord", config.TierInfo),
		{ID: "t", Time: t0, Kind: alerts.KindRead, Test: true, Process: &alerts.Process{Image: "/tmp/aba-test"}},
		mk("1", t0, "discord", config.TierInfo),
	}
	s := Suggest(list, nil)
	if len(s) != 1 {
		t.Fatalf("%+v", s)
	}
	g := s[0]
	if g.Count != 3 || g.Tier != config.TierWarn || !g.Last.Equal(t0.Add(2*time.Hour)) || len(g.Rule.Baits) != 2 || len(g.Alerts) != 3 || g.Alerts[0] != "3" || len(g.ID) != 12 {
		t.Fatalf("%+v", g)
	}
	if g.Recommended() {
		t.Fatal("a warn one is recommended")
	}
	if again := Suggest(list, nil); again[0].ID != g.ID {
		t.Fatal("ID not stable")
	}
	// Trusted for both baits: no suggestion. For one only: still suggested.
	if s := Suggest(list, []config.IgnoreRule{g.Rule}); len(s) != 0 {
		t.Fatalf("%+v", s)
	}
	part := g.Rule
	part.Baits = []string{"aws"}
	if s := Suggest(list, []config.IgnoreRule{part}); len(s) != 1 {
		t.Fatalf("%+v", s)
	}
}
