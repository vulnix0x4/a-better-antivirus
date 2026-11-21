package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The summary anyone may read must not give away where the baits are, what
// they're called, which programs were trusted or what touched what.
func TestPublicStatusGivesNothingAway(t *testing.T) {
	cfg := Default()
	cfg.User = UserInfo{Name: `PC\bob`, Profile: `C:\Users\bob`, Variant: "c0ffee"}
	cfg.Baits = []BaitConfig{{ID: "discord"}, {ID: "custom-1a2b", Path: `C:\Users\bob\Documents\bank logins.txt`}}
	cfg.Ignore = []IgnoreRule{{Path: `C:\Users\bob\AppData\Local\Programs\MyTool\tool.exe`, Signer: "MyTool Inc", Baits: []string{"discord"}}}
	st := NewState()
	st.Baits["discord"] = &BaitState{ID: "discord", Name: "Discord token store", Status: "ok",
		Files: []BaitFile{{Path: `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000041.ldb`, Text: "secret bait text"}}}
	st.Baits["custom-1a2b"] = &BaitState{ID: "custom-1a2b", Name: "bank logins.txt (custom)", Status: "error", StatusNote: `C:\Users\bob\Documents\bank logins.txt: denied`}
	st.Baits["opera"] = &BaitState{ID: "opera", Status: "retired"}
	st.Persona = map[string]string{"email": "jordan.marsh1987@outlook.com"}
	st.Frozen = []FrozenProcess{{PID: 4242, Image: `C:\Users\bob\Downloads\crack.exe`, AlertID: "20260101-000000-abcd"}}
	st.Blocked = []BlockedProgram{{Path: `C:\Users\bob\Downloads\crack.exe`}}
	st.Isolation = &Isolation{Since: time.Now(), AlertID: "20260101-000000-abcd"}
	st.Health = []HealthItem{{Name: "Baits", OK: false, Detail: "1 of 2 healthy"}}
	st.Bookmark = "<BookmarkList/>"

	cfg.LearningUntil = time.Now().Add(48 * time.Hour)
	p := MakePublic(cfg, st, "v9.9.9", 7, 2)
	b, _ := json.Marshal(p)
	// Nor how ABA would respond: "alerts only" or "learning" would tell a
	// stealer that nothing stops it.
	for _, secret := range []string{"bob", "discord", "Discord", "ldb", "leveldb", "bank", "custom", "MyTool", "tool.exe", "crack", "4242",
		"jordan", "secret bait text", "c0ffee", "abcd", "Bookmark", "opera",
		"balanced", "preset", "freeze", "block_program", "learning", "responses"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the public status mentions %q: %s", secret, b)
		}
	}
	if p.Baits != 2 || p.BaitsHealthy != 1 || p.Frozen != 1 || p.Blocked != 1 || p.IsolatedSince == nil || p.Alerts != 7 || p.OpenAlerts != 2 {
		t.Fatalf("counts: %+v", p)
	}
	// And the dashboard can still be drawn from it.
	c2, s2 := p.View()
	healthy := 0
	for _, bs := range s2.Baits {
		if bs.Status == "ok" {
			healthy++
		}
	}
	if c2.Preset != "" || len(c2.Responses) != 0 || !c2.LearningUntil.IsZero() || len(s2.Baits) != 2 || healthy != 1 || len(s2.Frozen) != 1 || s2.Isolation == nil || s2.ServiceVersion != "v9.9.9" {
		t.Fatalf("view: %+v %+v", c2, s2)
	}
}
