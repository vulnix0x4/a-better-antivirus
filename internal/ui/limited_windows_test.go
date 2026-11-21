package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// Without admin rights ABA's own files can't be read (they list every bait).
// The dashboard must still say whether you're protected, from the summary the
// service publishes, and must not show what it can't know.
func TestDashboardWithoutAdminRights(t *testing.T) {
	cfg := config.Default()
	st := config.NewState()
	st.Heartbeat = time.Now().Add(-20 * time.Second)
	st.Health = []config.HealthItem{{Name: "File auditing", OK: true, Detail: "on"}}
	st.Baits["discord"] = &config.BaitState{ID: "discord", Name: "Discord token store", Status: "ok",
		Files: []config.BaitFile{{Path: `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000041.ldb`}}}
	st.Baits["desktop-passwords"] = &config.BaitState{ID: "desktop-passwords", Name: "password list on the Desktop", Status: "ok"}
	st.Frozen = []config.FrozenProcess{{PID: 7712, Image: `C:\Users\bob\Downloads\crack.exe`}}
	pub := config.MakePublic(cfg, st, "v1.2.3", 5, 1)

	c2, s2 := pub.View()
	out := RenderStatus(StatusData{Cfg: c2, State: s2, Service: svcctl.Running, Limited: true, AlertCount: pub.Alerts, OpenCount: pub.OpenAlerts})
	for _, want := range []string{"RESPONSE ACTIVE", "1 process frozen", "2 of 2 baits healthy", "1 alert is waiting", "aba alerts", "v1.2.3", "File auditing"} {
		if !strings.Contains(out, want) {
			t.Errorf("dashboard missing %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{"discord", "Discord", "crack.exe", "bob", "ldb", "Balanced", "alert only", "frozen +", "internet cut"} {
		if strings.Contains(out, secret) {
			t.Errorf("the summary dashboard shows %q", secret)
		}
	}

	// End to end, against a locked folder: LoadStatus falls back to the summary.
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the rest is about running without admin rights")
	}
	root := t.TempDir()
	t.Setenv("ProgramData", root)
	if err := os.MkdirAll(paths.PublicDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SavePublic(pub); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(paths.AlertsDir(), 0o755)
	alerts.Save(&alerts.Alert{ID: "20260101-000000-abcd", Title: "secret alert", Status: "open"})
	defer func() { // hand the folders back so the test can clean up
		for _, d := range []string{paths.DataDir(), paths.PublicDir()} {
			config.SetSDDL(d, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
		}
	}()
	if err := config.LockDataDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(paths.DataDir(), "config.json")); !os.IsPermission(err) {
		t.Fatalf("config.json should be unreadable now: %v", err)
	}
	d := LoadStatus()
	if d.Err != nil || !d.Limited || d.Cfg == nil || d.State == nil || len(d.Alerts) != 0 || d.OpenCount != 1 {
		t.Fatalf("LoadStatus without access: %+v", d)
	}
	if out := RenderStatus(d); strings.Contains(out, "secret alert") || !strings.Contains(out, "2 of 2 baits healthy") {
		t.Fatalf("limited dashboard:\n%s", out)
	}
}
