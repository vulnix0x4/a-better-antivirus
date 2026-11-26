package ui

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
)

// Keys as a terminal sends them.
const (
	enter = "\r"
	down  = "\x1b[B"
	esc   = "\x1b"
)

func wizardInput() WizardInput {
	u := config.UserInfo{Name: `PC\bob`, Profile: `C:\Users\bob`, Desktop: `C:\Users\bob\Desktop`, Documents: `C:\Users\bob\Documents`,
		Downloads: `C:\Users\bob\Downloads`, LocalAppData: `C:\Users\bob\AppData\Local`, RoamingAppData: `C:\Users\bob\AppData\Roaming`}
	plan := baits.Plan(u, nil)
	for i := range plan {
		plan[i].Available = true
	}
	return WizardInput{User: u, Plan: plan}
}

// drive runs the real setup form, typing keys one at a time the way a person
// would (each key waits for the screen to settle), and returns its result.
func drive(t *testing.T, in WizardInput, keys ...string) (install.Options, bool, error) {
	t.Helper()
	w := newWizard(in)
	r, wr := io.Pipe()
	f := w.form.WithInput(r).WithOutput(io.Discard)
	errc := make(chan error, 1)
	go func() { errc <- f.Run() }()
	go func() {
		for _, k := range keys {
			time.Sleep(120 * time.Millisecond)
			if _, err := wr.Write([]byte(k)); err != nil {
				return
			}
		}
	}()
	select {
	case err := <-errc:
		wr.Close()
		if err == huh.ErrUserAborted {
			return install.Options{}, false, nil
		}
		if err != nil {
			return install.Options{}, false, err
		}
		o, ok := w.finish()
		return o, ok, nil
	case <-time.After(time.Duration(len(keys))*120*time.Millisecond + 5*time.Second):
		wr.Close()
		t.Fatalf("setup didn't finish after %d keys (stuck on a screen?)", len(keys))
		return install.Options{}, false, nil
	}
}

func TestSetupRecommendedJustEnter(t *testing.T) {
	// Recommended → phone: not now → clippers: yes → miners: yes → auto-update: yes
	// → Install (the review text needs no key).
	o, ok, err := drive(t, wizardInput(), enter, enter, enter, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Preset != "balanced" || o.Phone.Enabled() || !o.AutoUpdate || o.LearningDays != 0 || o.CanaryEmail != "" || !o.CleanRecent {
		t.Fatalf("recommended defaults: %+v", o)
	}
	if o.ClipboardBait == nil || !*o.ClipboardBait || o.MinerTrap == nil || !*o.MinerTrap {
		t.Fatalf("both traps are recommended: %v %v", o.ClipboardBait, o.MinerTrap)
	}
	want := 0
	for _, a := range wizardInput().Plan {
		if a.Spec.Default {
			want++
		}
	}
	if len(o.Baits) != want {
		t.Fatalf("baits: got %d, want the %d recommended", len(o.Baits), want)
	}
}

func TestSetupRecommendedWithNtfyNoUpdates(t *testing.T) {
	// Recommended → phone: ntfy → topic, server, token (the steps above them need no key)
	// → clippers, miners: yes → auto-update: n → Install.
	o, ok, err := drive(t, wizardInput(), enter, down, enter, enter, enter, enter, enter, enter, "n", enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Phone.Kind != "ntfy" || o.Phone.Ntfy.Server != "https://ntfy.sh" || len(o.Phone.Ntfy.Topic) < 8 {
		t.Fatalf("ntfy: %+v", o.Phone)
	}
	if o.AutoUpdate {
		t.Fatal("answered No to automatic updates")
	}
}

func TestSetupCustomizeStrictWithLearning(t *testing.T) {
	// Customize → baits (keep) → response: Strict → learning: 3 days → phone: not now
	// → clippers, miners: yes → canary: No → recent files: Yes → auto-update: Yes → Install.
	o, ok, err := drive(t, wizardInput(), down, enter, enter, down, enter, enter, enter, enter, enter, enter, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Preset != "strict" || o.LearningDays != 3 || o.KeepLearning {
		t.Fatalf("strict + learning: preset=%s learning=%d keep=%v", o.Preset, o.LearningDays, o.KeepLearning)
	}
}

func TestSetupCancelAtReview(t *testing.T) {
	_, ok, err := drive(t, wizardInput(), enter, enter, enter, enter, enter, "n")
	if err != nil || ok {
		t.Fatalf("Cancel must not install: ok=%v err=%v", ok, err)
	}
}

func TestSetupEscapeQuits(t *testing.T) {
	_, ok, err := drive(t, wizardInput(), "\x03")
	if err != nil || ok {
		t.Fatalf("ctrl+c must not install: ok=%v err=%v", ok, err)
	}
}

func TestSetupRerunKeepSettings(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.ApplyPreset("strict")
	ex.AutoUpdate = false
	ex.Version = config.CurrentConfigVersion
	ex.Baits = []config.BaitConfig{{ID: "desktop-passwords"}, {ID: "discord"}, {ID: "custom-1234", Path: `D:\secret.txt`}}
	in.Existing = ex
	in.Secrets = &config.Secrets{Phone: config.PhoneConfig{Kind: "discord", Discord: config.DiscordConfig{WebhookURL: "https://discord.com/api/webhooks/1/x"}}}
	// Keep my settings → review → Apply.
	o, ok, err := drive(t, in, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Preset != "strict" || o.AutoUpdate || o.Phone.Kind != "discord" || len(o.CustomBaits) != 1 || len(o.Baits) != 2 || !o.KeepLearning {
		t.Fatalf("keep must keep everything: %+v", o)
	}
}

func TestSetupGoBackAndChangeYourMind(t *testing.T) {
	// Recommended → phone: ntfy → shift+tab back → up to "Not now" → clippers, miners
	// → auto-update → Install.
	const back, up = "\x1b[Z", "\x1b[A"
	o, ok, err := drive(t, wizardInput(), enter, down, enter, back, up, enter, enter, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Phone.Enabled() {
		t.Fatalf("went back and chose Not now, got %+v", o.Phone)
	}
}

// `aba install --yes --keep-settings` (what the setup program runs on a PC
// that already has ABA): the same result as choosing "Keep my settings", with
// no form shown.
func TestKeepOptionsChangesNothing(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.ApplyPreset("strict")
	ex.AutoUpdate = false
	ex.CleanRecent = false
	ex.PhoneMinTier = config.TierCritical
	ex.Version = config.CurrentConfigVersion
	ex.Baits = []config.BaitConfig{{ID: "desktop-passwords"}, {ID: "discord"}, {ID: "custom-1234", Path: `D:\secret.txt`}}
	in.Existing = ex
	in.Secrets = &config.Secrets{Phone: config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Server: "https://ntfy.sh", Topic: "aba-keepme"}}}
	in.Secrets.Canary.Email = "me@example.com"

	o := KeepOptions(in)
	if o.Preset != "strict" || o.AutoUpdate || o.CleanRecent || o.PhoneMinTier != config.TierCritical || !o.KeepLearning {
		t.Fatalf("settings changed: %+v", o)
	}
	if o.Phone.Ntfy.Topic != "aba-keepme" || o.CanaryEmail != "me@example.com" {
		t.Fatalf("phone alerts or canary tokens changed: %+v", o)
	}
	if len(o.Baits) != 2 || len(o.CustomBaits) != 1 || o.CustomBaits[0] != `D:\secret.txt` {
		t.Fatalf("baits changed: %v + %v", o.Baits, o.CustomBaits)
	}
}

// An install from before automatic updates existed was never asked about
// them. The guided setup asks; a setup with no questions leaves them off.
func TestKeepOptionsDoesNotTurnOnUpdatesUnasked(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.Version = 1
	ex.AutoUpdate = false
	ex.Baits = []config.BaitConfig{{ID: "desktop-passwords"}}
	in.Existing = ex
	if o := KeepOptions(in); o.AutoUpdate {
		t.Fatal("automatic updates were switched on without asking")
	}
}

// Recommended, answering No to both traps.
func TestSetupRecommendedTrapsOff(t *testing.T) {
	o, ok, err := drive(t, wizardInput(), enter, enter, "n", "n", enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.ClipboardBait == nil || *o.ClipboardBait || o.MinerTrap == nil || *o.MinerTrap {
		t.Fatalf("answered No to both: %v %v", o.ClipboardBait, o.MinerTrap)
	}
}

// One yes, one no: each answer goes where it belongs.
func TestSetupRecommendedOnlyClippers(t *testing.T) {
	o, ok, err := drive(t, wizardInput(), enter, enter, enter, "n", enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.ClipboardBait == nil || !*o.ClipboardBait || o.MinerTrap == nil || *o.MinerTrap {
		t.Fatalf("clippers yes, miners no: %v %v", o.ClipboardBait, o.MinerTrap)
	}
}

// An install from before setup asked about the traps: "Keep my settings"
// asks the two questions once, and changes nothing else.
func TestSetupKeepAsksTrapsOnce(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.ApplyPreset("strict")
	ex.AutoUpdate = false
	ex.Version = config.TrapsAskedSince - 1
	ex.Baits = []config.BaitConfig{{ID: "desktop-passwords"}}
	in.Existing = ex
	// Keep my settings → clippers: yes → miners: no → Apply.
	o, ok, err := drive(t, in, enter, enter, "n", enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.ClipboardBait == nil || !*o.ClipboardBait || o.MinerTrap == nil || *o.MinerTrap {
		t.Fatalf("answers: %v %v", o.ClipboardBait, o.MinerTrap)
	}
	if o.Preset != "strict" || o.AutoUpdate || len(o.Baits) == 0 || !o.KeepLearning {
		t.Fatalf("everything else must be kept: %+v", o)
	}
	// Asked once: a config saved by this version isn't asked again.
	ex.Version = config.CurrentConfigVersion
	ex.ClipboardBait, ex.MinerTrap = true, false
	o, ok, err = drive(t, in, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.ClipboardBait != nil || o.MinerTrap != nil {
		t.Fatalf("asked again, or changed: %v %v", o.ClipboardBait, o.MinerTrap)
	}
}

// Changing settings shows the traps as they are now.
func TestSetupChangeShowsTrapsAsTheyAre(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.Version = config.CurrentConfigVersion
	ex.Baits = []config.BaitConfig{{ID: "desktop-passwords"}}
	ex.ClipboardBait, ex.MinerTrap = false, true
	in.Existing, in.Change = ex, true
	// Change settings (already selected) → baits → response → phone → traps as
	// they are → canary → recent → updates → Apply.
	o, ok, err := drive(t, in, enter, enter, enter, enter, enter, enter, enter, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.ClipboardBait == nil || *o.ClipboardBait || o.MinerTrap == nil || !*o.MinerTrap {
		t.Fatalf("defaults should be what's set: %v %v", o.ClipboardBait, o.MinerTrap)
	}
}

// The setup program on a PC that has ABA (and `aba install --yes
// --keep-settings`): never switches a trap on, asked or not.
func TestKeepOptionsLeavesTrapsAlone(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.Version = config.TrapsAskedSince - 1
	in.Existing = ex
	if o := KeepOptions(in); o.ClipboardBait != nil || o.MinerTrap != nil {
		t.Fatalf("traps changed without asking: %v %v", o.ClipboardBait, o.MinerTrap)
	}
}

func TestReviewMentionsTraps(t *testing.T) {
	on := reviewSummary(modeRecommended, 17, "balanced", "", "", false, true, "0", false, trapAnswers{asked: true, clipOK: true, minerOK: true, clippers: true, miners: true})
	off := reviewSummary(modeRecommended, 17, "balanced", "", "", false, true, "0", false, trapAnswers{asked: true, clipOK: true, minerOK: true})
	if !strings.Contains(on, "Clippers") || !strings.Contains(on, "Miners") || !strings.Contains(on, "fake mining pool") {
		t.Errorf("on: %s", on)
	}
	if !strings.Contains(off, "aba clipboard on") || !strings.Contains(off, "aba miners on") {
		t.Errorf("off: %s", off)
	}
	keep := reviewSummary(modeKeep, 17, "balanced", "", "", false, true, "0", false, trapAnswers{asked: true, clipOK: true, minerOK: true, miners: true})
	if !strings.Contains(keep, "And from now on") || !strings.Contains(keep, "aba clipboard on") {
		t.Errorf("keep: %s", keep)
	}
	if k := reviewSummary(modeKeep, 17, "balanced", "", "", false, true, "0", false, trapAnswers{clipOK: true, minerOK: true}); strings.Contains(k, "Miners") {
		t.Errorf("keep, not asked: %s", k)
	}
}
