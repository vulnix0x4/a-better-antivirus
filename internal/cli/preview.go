//go:build preview

package cli

import (
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/origin"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// Screen is one rendered terminal screen for design review.
type Screen struct{ Name, ANSI string }

// Previews renders every screen people see, from sample data.
func Previews() []Screen {
	var out []Screen
	add := func(name, s string) { out = append(out, Screen{name, s}) }

	add("01-welcome", renderWelcome())
	add("02-help", rootHelp(newRoot()))

	u := config.UserInfo{Name: `DESKTOP-7Q2\bob`, Profile: `C:\Users\bob`, Desktop: `C:\Users\bob\Desktop`, Documents: `C:\Users\bob\Documents`,
		Downloads: `C:\Users\bob\Downloads`, LocalAppData: `C:\Users\bob\AppData\Local`, RoamingAppData: `C:\Users\bob\AppData\Roaming`}
	plan := baits.Plan(u, nil)
	for i := range plan {
		plan[i].Available, plan[i].Reason = true, ""
		if plan[i].Spec.ID == "telegram" {
			plan[i].Available, plan[i].Reason = false, "Telegram Desktop is installed"
		}
	}
	in := ui.WizardInput{User: u, Plan: plan}
	header := ui.Banner("setup") + "\n\n"
	for i, v := range ui.PreviewWizard(in, "recommended", "ntfy") {
		add("10-setup-recommended-"+string(rune('a'+i)), header+v)
	}
	for i, v := range ui.PreviewWizard(in, "custom", "") {
		add("11-setup-custom-"+string(rune('a'+i)), header+v)
	}
	cfg := config.Default()
	in.Existing = cfg
	for i, v := range ui.PreviewWizard(in, "keep", "") {
		add("12-setup-existing-"+string(rune('a'+i)), header+v)
	}

	steps := []ui.PreviewStep{
		{"Checking this PC", "done", `protecting DESKTOP-7Q2\bob · C:\Users\bob`},
		{"Cleaning up older versions", "done", "nothing to clean up"},
		{"Stopping the running service", "done", "first install"},
		{"Installing program files", "done", `C:\Program Files\File Access Monitor`},
		{"Locking down the data folder", "done", "only admins can change it"},
		{"Saving your settings", "done", "Balanced (recommended) · 17 baits · automatic updates"},
		{"Turning on Windows file auditing", "running", ""},
		{"Planting baits", "pending", ""},
		{"Starting the background service", "pending", ""},
		{"Adding aba to your PATH", "pending", ""},
		{"Sending a test to your phone", "pending", ""},
	}
	add("20-install-running", header+ui.PreviewSteps("Setting up A Better Antivirus", steps, 0))
	for i := range steps {
		steps[i].State = "done"
	}
	steps[6].Detail = "how ABA sees who opens a bait"
	steps[7].Detail = "17 in place"
	steps[8].Detail = `"File Access Monitor", starts with Windows`
	steps[10].Detail = "sent via ntfy (https://ntfy.sh/aba-k3…): check your phone"
	add("21-install-done", header+ui.PreviewSteps("Setting up A Better Antivirus", steps, 6300*time.Millisecond)+"\n"+
		renderDoneCard(sampleConfig(), sampleState(), &config.Secrets{Phone: config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Server: "https://ntfy.sh", Topic: "aba-k3m9xq2p7d"}}}, true))

	d := ui.StatusData{Cfg: sampleConfig(), State: sampleState(), Service: svcctl.Running, At: time.Now(),
		Alerts: []*alerts.Alert{sampleAlert(), infoAlert()}}
	add("30-dashboard-incident", ui.RenderStatus(d))
	calm := sampleState()
	calm.Frozen, calm.Blocked = nil, nil
	add("31-dashboard-calm", ui.RenderStatus(ui.StatusData{Cfg: sampleConfig(), State: calm, Service: svcctl.Running, At: time.Now(), Alerts: []*alerts.Alert{infoAlert()}}))
	add("32-dashboard-empty", ui.RenderStatus(ui.StatusData{Cfg: sampleConfig(), State: calm, Service: svcctl.Running, At: time.Now()}))
	add("40-alert-detail", ui.AlertDetail(sampleAlert()))
	ta := sampleAlert()
	ta.Test, ta.ID = true, "20261118-190455-7c21"
	add("22-safe-test", ui.Banner("safe test")+"\n\n"+ui.Plain.Render(" A harmless copy of ABA in your Temp folder is about to read passwords.txt on the Desktop,\n exactly the way a stealer would.")+"\n\n"+renderTestResult(ta, "ntfy"))
	add("41-alert-list", ui.AlertTable([]*alerts.Alert{browserKeptAlert(), browserStealerAlert(), sampleAlert(), infoAlert(), sweepAlert()}, ui.Width()))
	add("42-alert-browser-stealer", ui.AlertDetail(browserStealerAlert()))
	add("43-alert-browser-kept", ui.AlertDetail(browserKeptAlert()))
	return out
}

const previewChrome = `C:\Program Files\Google\Chrome\Application\chrome.exe`

// browserStealerAlert: a stealer started Chrome suspended and ran its code
// inside it, which went through the fake profile (see engine's host.go).
func browserStealerAlert() *alerts.Alert {
	stealer := `C:\Users\bob\AppData\Local\Temp\cl3v\chromelevator.exe`
	why := "Chrome was started suspended by chromelevator.exe and never ran as a browser, then went through a fake profile only a stealer would open: that's a stealer running its own code inside a genuine Chrome, to get at the passwords and cookies it protects"
	a := &alerts.Alert{
		ID: "20261123-101722-b7e1", Time: time.Now().Add(-2 * time.Minute), Kind: alerts.KindRead, Tier: config.TierCritical,
		Title: "Possible stealer inside Chrome: a hidden copy of it opened your bait", Status: "open", LatencyMS: 9, Instant: true,
		Summary: "Caught the moment it opened the bait (instant freeze). " + why,
		Baits:   []alerts.BaitHit{{Name: "extra profile inside your Chrome", Path: `C:\Users\bob\AppData\Local\Google\Chrome\User Data\Profile 23\Network\Cookies`, Access: "read", Time: time.Now()}},
		Process: &alerts.Process{PID: 9120, Image: previewChrome, CommandLine: `"` + previewChrome + `"`, User: `DESKTOP-7Q2\bob`,
			Signature: provenance.Result{Signed: true, Valid: true, Signer: "Google LLC"},
			Parents:   []procinfo.Parent{{PID: 9088, Image: stealer}, {PID: 4410, Image: `C:\Windows\explorer.exe`}}},
		Verdict: classify.Verdict{Tier: config.TierCritical, Host: true, Reasons: []string{why,
			"created suspended: its first thread never ran, so it never got to be a browser; code was put into it instead",
			"started by " + stealer + ": unsigned program running from a user-writable folder (C:\\Users\\bob\\AppData\\Local\\Temp\\cl3v): typical of stealers",
			"ABA froze that Chrome, all of it, not the Chrome windows you use"}},
	}
	a.AddAction(config.ActionFreeze, nil, "4 process(es) frozen: that whole Chrome, from its main process (pid 9120) the moment it opened the bait; with it: chromelevator.exe (pid 9088)")
	a.AddAction(config.ActionBlockProgram, nil, stealer)
	return a
}

// browserKeptAlert: something inside the Chrome you're using went through
// the fake profile; it's left running, its internet cut.
func browserKeptAlert() *alerts.Alert {
	why := "Chrome opened a fake profile that only a stealer would open: something is running inside the Chrome you're using (an add-on, or code a stealer put into it)"
	a := &alerts.Alert{
		ID: "20261123-094410-5c0d", Time: time.Now().Add(-40 * time.Minute), Kind: alerts.KindRead, Tier: config.TierCritical,
		Title: "Something inside your Chrome read a bait: its internet is cut", Status: "open",
		Summary: why + ". ABA left it running, since it's the browser you're using, and cut the internet of every Chrome window instead",
		Baits:   []alerts.BaitHit{{Name: "extra profile inside your Chrome", Path: `C:\Users\bob\AppData\Local\Google\Chrome\User Data\Profile 23\Login Data`, Access: "read", Time: time.Now()}},
		Process: &alerts.Process{PID: 5532, Image: previewChrome, User: `DESKTOP-7Q2\bob`,
			Signature: provenance.Result{Signed: true, Valid: true, Signer: "Google LLC"},
			Parents:   []procinfo.Parent{{PID: 4410, Image: `C:\Windows\explorer.exe`}}},
		Verdict: classify.Verdict{Tier: config.TierCritical, Host: true, KeepRunning: true, Reasons: []string{why,
			"it has a window on your screen, and nothing about how it was started is unusual: it's the browser you're using, so ABA doesn't freeze it (you'd lose your work)"}},
	}
	a.AddAction(config.ActionBlockProgram, nil, previewChrome)
	a.AddAction(config.ActionLeftRunning, nil, "it's the Chrome you're using; the internet of every Chrome window is cut instead")
	return a
}

func sampleConfig() *config.Config {
	c := config.Default()
	c.AutoUpdate = true
	return c
}

func sampleState() *config.State {
	st := config.NewState()
	st.Heartbeat = time.Now().Add(-40 * time.Second)
	st.ServiceVersion = "v0.5.0"
	st.Health = []config.HealthItem{{Name: "File auditing", OK: true, Detail: "on"}, {Name: "Instant freeze", OK: true, Detail: "17 baits guarded"}}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q"} {
		st.Baits[id] = &config.BaitState{Status: "ok"}
	}
	st.Frozen = []config.FrozenProcess{{PID: 7712}}
	st.Blocked = []config.BlockedProgram{{Path: "x"}}
	return st
}

func sampleAlert() *alerts.Alert {
	a := &alerts.Alert{
		ID: "20261116-151253-9f3a", Time: time.Now().Add(-3 * time.Minute), Kind: alerts.KindRead, Tier: config.TierCritical,
		Title: "Possible stealer: svch0st.exe opened your bait", Status: "open", LatencyMS: 131, Instant: true,
		Summary: `Caught the moment it opened the bait (instant freeze). unsigned program running from a user-writable folder (C:\Users\bob\AppData\Local\Temp\x7f3): typical of stealers`,
		Baits: []alerts.BaitHit{
			{Name: "passwords.txt on the Desktop", Path: `C:\Users\bob\Desktop\passwords.txt`, Access: "read", Time: time.Now()},
			{Name: "Exodus wallet", Path: `C:\Users\bob\AppData\Roaming\Exodus\exodus.wallet\seed.seco`, Access: "read", Time: time.Now()},
		},
		Process: &alerts.Process{PID: 7712, Image: `C:\Users\bob\AppData\Local\Temp\x7f3\svch0st.exe`,
			CommandLine: `"C:\Users\bob\AppData\Local\Temp\x7f3\svch0st.exe" --silent`, User: `DESKTOP-7Q2\bob`,
			SHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Signature: provenance.Result{},
			Origin:      &origin.Origin{File: `C:\Users\bob\AppData\Local\Temp\x7f3\svch0st.exe`, URL: "https://files.example.net/d/x7f3/FL_Studio_full.zip"},
			Parents:     []procinfo.Parent{{PID: 6620, Image: `C:\Windows\System32\cmd.exe`}, {PID: 4410, Image: `C:\Windows\explorer.exe`}},
			Connections: []procinfo.Conn{{Proto: "tcp", Local: "192.168.1.20:51544", Remote: "185.234.72.11:443", State: "ESTABLISHED"}}},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{`unsigned program running from a user-writable folder (C:\Users\bob\AppData\Local\Temp\x7f3): typical of stealers`, "not signed"}},
	}
	a.AddAction(config.ActionFreeze, nil, "2 process(es) frozen the moment it opened the bait")
	a.AddAction(config.ActionBlockProgram, nil, a.Process.Image)
	return a
}

func infoAlert() *alerts.Alert {
	return &alerts.Alert{ID: "20261116-101500-11aa", Time: time.Now().Add(-5 * time.Hour), Tier: config.TierWarn, Kind: alerts.KindRead, Status: "resolved", Note: "you trusted this program",
		Title: "opencode.exe read a bait", Baits: []alerts.BaitHit{{Name: "AWS credentials (~/.aws)"}},
		Process: &alerts.Process{Image: `C:\Users\bob\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode.exe`, Signature: provenance.Result{Valid: true, Signer: "Anomaly Innovations, Inc."}}}
}

func sweepAlert() *alerts.Alert {
	a := &alerts.Alert{ID: "20261115-221709-c0de", Time: time.Now().Add(-26 * time.Hour), Tier: config.TierCritical, Kind: alerts.KindRead, Status: "resolved", Note: "killed",
		Title: "Possible stealer: explorer.exe read your bait", Baits: []alerts.BaitHit{{Name: "Discord token store"}, {Name: "Brave browser profile"}, {Name: "Exodus wallet"}},
		Process: &alerts.Process{Image: `C:\Windows\explorer.exe`, Signature: provenance.Result{Valid: true, Signer: "Microsoft Windows"}},
		Verdict: classify.Verdict{Swept: []string{"discord", "brave", "exodus"}}}
	a.AddAction(config.ActionBlockProgram, nil, "")
	return a
}

var _ = strings.TrimSpace
