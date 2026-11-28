package appapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// The locked view is built from config.Public only: nothing in it may name
// a bait, a path, a program or how ABA responds.
func TestLockedLeaksNothing(t *testing.T) {
	src, a := frozenSource(alerts.SentSome)
	cfg := baseConfig()
	cfg.Preset = "alert"
	p := config.MakePublic(cfg, src.State, "v0.10.2", len(src.Alerts), 1)
	b, _ := json.Marshal(LockedView(p, "v0.10.2", a.ID, now))
	s := strings.ToLower(string(b))
	for _, secret := range []string{"nitrogen", `\\users`, "discord", "chrome", "passwords", "alert only", "\"preset", "balanced", "9120", "token"} {
		if strings.Contains(s, strings.ToLower(secret)) {
			t.Errorf("locked view shows %q: %s", secret, b)
		}
	}
	// Only these fields, ever (a new one needs a look at what it shows).
	var m map[string]any
	json.Unmarshal(b, &m)
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	want := map[string]bool{"schema": true, "mode": true, "version": true, "state": true, "headline": true, "somethingFrozen": true,
		"isolated": true, "baits": true, "baitsHealthy": true, "openAlerts": true, "heartbeat": true, "health": true, "alert": true}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("new field in the locked view: %s", k)
		}
	}
	l := LockedView(p, "v0.10.2", a.ID, now)
	if l.State != "frozen" || !l.SomethingFrozen || l.Alert != a.ID {
		t.Errorf("got %+v", l)
	}
}

func TestLockedStates(t *testing.T) {
	if l := LockedView(nil, "v1", "", now); l.State != "stopped" {
		t.Errorf("no status: %s", l.State)
	}
	st := baseState()
	st.Heartbeat = now.Add(-10 * 60 * 1e9)
	if l := LockedView(config.MakePublic(baseConfig(), st, "v1", 0, 0), "v1", "", now); l.State != "stopped" {
		t.Errorf("stale: %s", l.State)
	}
	st = baseState()
	st.Baits["discord"].Status = "missing"
	if l := LockedView(config.MakePublic(baseConfig(), st, "v1", 0, 0), "v1", "", now); l.State != "attention" {
		t.Errorf("missing bait: %s", l.State)
	}
	if l := LockedView(config.MakePublic(baseConfig(), baseState(), "v1", 0, 0), "v1", "", now); l.State != "protected" || !reflect.DeepEqual(l.Health, healthItems(serviceHealth())) {
		t.Errorf("protected: %+v", l)
	}
}
