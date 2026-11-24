package engine

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
)

const (
	chromeExe   = `C:\Program Files\Google\Chrome\Application\chrome.exe`
	ghostExe    = `C:\Users\bob\AppData\Local\Temp\x\ghost.exe`
	explorerExe = `C:\Windows\explorer.exe`
	pythonExe   = `C:\Users\bob\AppData\Local\Programs\Python\Python312\python.exe`
)

// browserUser is chromeUser with a Chrome running: its main process (1000)
// and two of its own (1001, 1002), started by starter (0: it has exited).
// The engine doesn't wait for Chrome to adopt the folder (see adoptWait).
func browserUser(t *testing.T, preset string, starter uint32, starterImage string, mod func(b *procinfo.BrowserInstance)) (*Engine, *fakeOps, string, *procinfo.BrowserInstance) {
	t.Helper()
	e, f := setup(preset)
	bait, _ := chromeUser(t, e)
	st := stateWithAll()
	st.Baits["chrome-profile"] = &config.BaitState{ID: "chrome-profile", Name: "extra profile inside your Chrome",
		Files: []config.BaitFile{{Path: bait, Audit: true}, {Path: cookiesOf(bait), Audit: true}}}
	e.Configure(e.cfg, st)
	e.adoptWait = 0
	b := &procinfo.BrowserInstance{Main: 1000, MainCreate: 1, Image: chromeExe, CommandLine: `"` + chromeExe + `"`,
		PIDs: []uint32{1000, 1001, 1002}, Starter: starter, StarterImage: starterImage, StarterCreate: 1, StarterGone: starter == 0}
	if mod != nil {
		mod(b)
	}
	for _, p := range b.PIDs {
		f.browsers[p] = b
		f.images[p] = b.Image
	}
	signed(f, b.Image, "Google LLC")
	signed(f, explorerExe, "Microsoft Windows")
	signed(f, pythonExe, "Python Software Foundation")
	if starter != 0 {
		f.images[starter] = starterImage
		f.parents[b.Main] = []procinfo.Ancestor{{PID: starter, Image: starterImage, CreateTime: 1}, {PID: 4410, Image: explorerExe, CreateTime: 1}}
	}
	f.images[4410] = explorerExe
	return e, f, bait, b
}

func suspended(b *procinfo.BrowserInstance) { b.CreatedSuspended = true }

func cookiesOf(bait string) string {
	return strings.TrimSuffix(bait, "Login Data") + `Network\Cookies`
}

func hasP(pids []uint32, p uint32) bool { return hasPID(pids, p) }

func frozenPIDs(f *fakeOps) []uint32 {
	var out []uint32
	for _, x := range f.state.Frozen {
		out = append(out, x.PID)
	}
	return out
}

// The technique: a stealer starts the genuine Chrome suspended, runs its code
// inside it, and that code goes through every profile. That Chrome is frozen,
// all of it, from its main process, with the stealer; the stealer's internet
// is cut, Chrome's isn't (your own Chrome windows would lose it).
func TestBrowserCreatedSuspendedIsFrozenWithItsStarter(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	e.HandleAccess(ev(1001, chromeExe, bait, 1)) // one of its own processes opened it
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Verdict.Host || a.Verdict.KeepRunning || !a.Did(config.ActionFreeze) {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.suspended) != 2 || f.suspended[0] != 1000 || f.suspended[1] != 900 {
		t.Fatalf("want Chrome frozen from its main process, then ghost.exe: %v", f.suspended)
	}
	if fr := frozenPIDs(f); !hasP(fr, 1000) || !hasP(fr, 900) {
		t.Fatalf("on record as frozen (what `aba kill` ends): %v", fr)
	}
	if len(f.blocked) != 1 || f.blocked[0] != ghostExe {
		t.Fatalf("blocked %v: want the stealer, never chrome.exe", f.blocked)
	}
	for _, want := range []string{"started suspended by ghost.exe", "never ran as a browser"} {
		if !strings.Contains(a.Summary, want) {
			t.Errorf("summary %q lacks %q", a.Summary, want)
		}
	}
	if a.Title != "Possible stealer: a Chrome started suspended by ghost.exe read your bait" {
		t.Errorf("title: %q", a.Title)
	}
	if _, why := trust.Rule(a); why == "" || trust.OneClick(a) {
		t.Error("a browser going through a fake profile must never be trusted from the alert")
	}
	if len(f.desktop) != 1 {
		t.Fatalf("popups: %v", f.desktop)
	}
}

// A signed runtime that creates a suspended browser which then goes through
// a fake profile is the injector too (a Python script): frozen with it.
func TestRuntimeThatStartedASuspendedBrowserIsFrozen(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 901, pythonExe, suspended)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	if !hasP(f.suspended, 901) {
		t.Fatalf("python.exe that created the suspended Chrome: suspended %v", f.suspended)
	}
	for _, b := range f.blocked {
		if b == chromeExe || b == pythonExe {
			t.Fatalf("blocked %v: Chrome never; a signed runtime isn't blocked for everyone either", f.blocked)
		}
	}
}

// Started hidden by an unsigned program: the same.
func TestBrowserStartedHiddenByAStealer(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, func(b *procinfo.BrowserInstance) {
		b.Hidden = []string{"it was told to keep its window hidden"}
	})
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !hasP(f.suspended, 1000) || !hasP(f.suspended, 900) || f.asked != 0 {
		t.Fatalf("alert %+v, suspended %v, window checks %d", a, f.suspended, f.asked)
	}
	if !strings.Contains(a.Summary, "started hidden by ghost.exe") || len(f.blocked) != 1 || f.blocked[0] != ghostExe {
		t.Fatalf("summary %q, blocked %v", a.Summary, f.blocked)
	}
}

// Started normally by Explorer, but with no window on your screen (a
// headless copy someone else drives): the instance is frozen, Explorer
// never; nothing is blocked.
func TestBrowserWithNoWindowIsFrozenAlone(t *testing.T) {
	e, f, bait, b := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.parents[b.Main] = []procinfo.Ancestor{{PID: 4410, Image: explorerExe, CreateTime: 1}}
	f.visible[1000] = false
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || a.Verdict.KeepRunning || len(f.suspended) != 1 || f.suspended[0] != 1000 {
		t.Fatalf("alert %+v, suspended %v", a, f.suspended)
	}
	if len(f.blocked) != 0 || a.Did(config.ActionBlockProgram) {
		t.Fatalf("blocked %v", f.blocked)
	}
	if !strings.Contains(a.Summary, "has no window on your screen") {
		t.Errorf("summary: %q", a.Summary)
	}
}

// The browser you're using: started by you, with a window. Something in it
// went through the fake profile (an add-on, injected code). It's never
// frozen or killed, in any preset: its internet is cut instead, and you're
// told so. No autopsy: it reads your real cookies all day.
func TestTheBrowserYoureUsingKeepsRunning(t *testing.T) {
	for _, preset := range []string{"balanced", "strict"} {
		e, f, bait, _ := browserUser(t, preset, 4410, explorerExe, nil)
		f.visible[1000] = true
		e.HandleAccess(ev(1000, chromeExe, bait, 1))
		a := only(f)
		if a == nil || a.Tier != config.TierCritical || !a.Verdict.Host || !a.Verdict.KeepRunning {
			t.Fatalf("%s: alert %+v", preset, a)
		}
		if len(f.suspended) != 0 || len(f.resumed) != 0 || len(f.killed) != 0 || a.Did(config.ActionFreeze) {
			t.Fatalf("%s: suspended %v resumed %v killed %v", preset, f.suspended, f.resumed, f.killed)
		}
		if len(f.blocked) != 1 || f.blocked[0] != chromeExe || !a.Did(config.ActionBlockProgram) || !a.Did(config.ActionLeftRunning) {
			t.Fatalf("%s: blocked %v, actions %+v", preset, f.blocked, a.Actions)
		}
		if preset == "strict" && f.isolated != 1 {
			t.Fatalf("strict isolates the PC as usual: %d", f.isolated)
		}
		if !strings.Contains(a.Summary, "cut the internet of every Chrome window") || !strings.HasPrefix(a.Title, "Something inside your Chrome") {
			t.Fatalf("%s: %q / %q", preset, a.Title, a.Summary)
		}
		time.Sleep(20 * time.Millisecond)
		f.mu.Lock()
		cases := len(f.cases)
		f.mu.Unlock()
		if cases != 0 {
			t.Fatalf("%s: an autopsy of the browser you're using", preset)
		}
		if _, why := trust.Rule(a); why == "" || trust.OneClick(a) {
			t.Fatalf("%s: one click must not trust chrome.exe for its fake profile", preset)
		}
	}
}

// Visibility unknown (the check failed): treated as yours, never as hidden.
func TestUnknownVisibilityIsNeverHidden(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	if a := only(f); a == nil || !a.Verdict.KeepRunning || len(f.suspended) != 0 || f.asked != 1 {
		t.Fatalf("alert %+v, suspended %v, asked %d", a, f.suspended, f.asked)
	}
}

// Alert only: you're told, nothing is done, whichever browser it is.
func TestBrowserHostAlertOnly(t *testing.T) {
	e, f, bait, _ := browserUser(t, "alert", 4410, explorerExe, nil)
	f.visible[1000] = true
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || len(a.Actions) != 0 || len(f.blocked) != 0 || len(f.suspended) != 0 || len(f.desktop) != 1 {
		t.Fatalf("alert %+v, blocked %v", a, f.blocked)
	}
	e, f, bait, _ = browserUser(t, "alert", 900, ghostExe, suspended)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	if a := only(f); a == nil || a.Tier != config.TierCritical || len(a.Actions) != 0 || len(f.suspended) != 0 || len(f.desktop) != 1 {
		t.Fatalf("alert only, stealer's browser: %+v", a)
	}
}

// Already gone when ABA looked: no browser you use comes and goes in a
// moment. Critical; nothing to freeze, and Chrome's internet isn't cut.
func TestBrowserGoneBeforeABALooked(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	f.gone[1000] = true
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Verdict.Host || len(f.suspended) != 0 || len(f.blocked) != 0 {
		t.Fatalf("alert %+v, suspended %v, blocked %v", a, f.suspended, f.blocked)
	}
	if !strings.Contains(a.Summary, "already exited") || a.Did(config.ActionFreeze) || a.Did(config.ActionBlockProgram) {
		t.Fatalf("summary %q, actions %+v", a.Summary, a.Actions)
	}
}

// Its processes each open fake profile files: one alert, one freeze, one
// popup, per browser instance (a second suspension would survive `aba
// resume`).
func TestOneAlertPerBrowserInstance(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	e.HandleAccess(ev(1002, chromeExe, cookiesOf(bait), 1))
	e.HandleAccess(ev(1000, chromeExe, cookiesOf(bait), 1))
	a := only(f)
	if len(f.saved) != 1 || len(f.desktop) != 1 || len(f.suspended) != 2 || len(a.Baits) != 2 {
		t.Fatalf("alerts %d, popups %d, suspended %v, baits %d", len(f.saved), len(f.desktop), f.suspended, len(a.Baits))
	}

	e, f, bait, _ = browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	e.HandleAccess(ev(1001, chromeExe, bait, 1))
	e.HandleAccess(ev(1002, chromeExe, cookiesOf(bait), 1))
	if len(f.saved) != 1 || len(f.desktop) != 1 || len(f.blocked) != 1 || f.asked != 1 {
		t.Fatalf("the browser you're using: alerts %d, popups %d, blocked %v, window checks %d", len(f.saved), len(f.desktop), f.blocked, f.asked)
	}
}

// Two of its processes reported at once, by different workers: still one.
func TestOneAlertPerBrowserInstanceAtOnce(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	done := make(chan bool)
	go func() { e.HandleAccess(ev(1001, chromeExe, bait, 1)); done <- true }()
	go func() { e.HandleAccess(ev(1002, chromeExe, cookiesOf(bait), 1)); done <- true }()
	<-done
	<-done
	if len(f.saved) != 1 || len(f.desktop) != 1 || f.asked != 1 {
		t.Fatalf("alerts %d, popups %d, window checks %d", len(f.saved), len(f.desktop), f.asked)
	}
}

// You added a profile and Chrome reached that folder's name: it writes that
// down a moment after it opens the folder. Then it's Chrome's own data.
func TestBrowserAdoptingTheFolderMeanwhile(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	localState := strings.TrimSuffix(bait, `Profile 23\Login Data`) + "Local State"
	f.onVisible = func() {
		os.WriteFile(localState, []byte(`{"profile":{"info_cache":{"Default":{},"Profile 23":{"name":"Work"}}}}`), 0o644)
	}
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	a := only(f)
	if a == nil || a.Kind != alerts.KindDecoyRetired || len(f.retired) != 1 || len(f.blocked) != 0 || a.Verdict.KeepRunning {
		t.Fatalf("alert %+v, retired %v, blocked %v", a, f.retired, f.blocked)
	}
}

// A browser installed in your own folders looks unsigned in a user folder
// until its signature is checked: it isn't frozen on that first guess.
func TestPerUserBrowserNotFrozenOnTheFirstGuess(t *testing.T) {
	e, f, bait, _ := browserUser(t, "strict", 4410, explorerExe, func(b *procinfo.BrowserInstance) {})
	perUser := strings.TrimSuffix(e.cfg.User.LocalAppData, `\`) + `\Google\Chrome\Application\chrome.exe`
	for _, p := range []uint32{1000, 1001, 1002} {
		f.images[p] = perUser
		f.browsers[p].Image = perUser
	}
	signed(f, perUser, "Google LLC")
	f.visible[1000] = true
	e.HandleAccess(ev(1000, perUser, bait, 1))
	a := only(f)
	if a == nil || !a.Verdict.KeepRunning || len(f.suspended) != 0 || len(f.resumed) != 0 {
		t.Fatalf("alert %+v, suspended %v, resumed %v", a, f.suspended, f.resumed)
	}
}

// Inside the open: a browser the quick facts show isn't yours is frozen
// right there, from its main process, with its starter; the browser you're
// using (or one that needs its windows checked) is left to the event log,
// in strict too.
func TestInstantDecisionsForABrowser(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	e.cfg.InstantFreeze = true
	if ok, why := e.DecideInstantOpWhy(1001, bait, 0); !ok {
		t.Fatalf("a suspended Chrome started by ghost.exe: %s", why)
	}
	if roots, inst := e.InstantRoots(1001); !inst || len(roots) != 2 || roots[0] != 1000 || roots[1] != 900 {
		t.Fatalf("roots %v (instance %v)", roots, inst)
	}
	// The service freezes those and reports it; the event log's reports of
	// what its processes did then join that alert.
	e.ClaimAll([]uint32{1000, 1001, 1002, 900})
	e.HandleOpen(1001, bait, time.Now(), []uint32{1000, 1001, 1002, 900})
	e.HandleAccess(ev(1002, chromeExe, cookiesOf(bait), 1))
	a := only(f)
	if len(f.saved) != 1 || len(f.suspended) != 0 || a == nil || !a.Instant || len(a.Baits) != 2 {
		t.Fatalf("alerts %d, suspended again %v, alert %+v", len(f.saved), f.suspended, a)
	}
	if len(f.blocked) != 1 || f.blocked[0] != ghostExe {
		t.Fatalf("blocked %v", f.blocked)
	}

	for _, preset := range []string{"balanced", "strict"} {
		e, f, bait, _ = browserUser(t, preset, 4410, explorerExe, nil)
		e.cfg.InstantFreeze = true
		f.visible[1000] = true
		if ok, why := e.DecideInstantOpWhy(1000, bait, 0); ok {
			t.Fatalf("%s: the browser you're using frozen inside the open (%s)", preset, why)
		}
		if f.asked != 0 {
			t.Fatalf("%s: the window check is the event log's (it takes a while)", preset)
		}
	}
	e, f, bait, _ = browserUser(t, "balanced", 4410, explorerExe, func(b *procinfo.BrowserInstance) {
		b.Flags = []string{"--headless"}
	})
	e.cfg.InstantFreeze = true
	if ok, _ := e.DecideInstantOpWhy(1000, bait, 0); ok {
		t.Fatal("only switches on its command line: its windows decide, in the event log")
	}
	e, f, bait, _ = browserUser(t, "balanced", 900, ghostExe, suspended)
	e.cfg.InstantFreeze = true
	f.gone[1000] = true
	if ok, _ := e.DecideInstantOpWhy(1000, bait, 0); ok {
		t.Fatal("a process that has exited")
	}
}

// You add a profile and the browser reaches the fake's folder name: the
// browser you're using deletes the fake's files, makes the folder a real
// profile, and lists it seconds later. That's the browser at work, not a
// stealer: no internet cut, plain words, and the fake profile is moved.
func TestBrowserTakingTheFolderForANewProfile(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	e.takeWait = 3 * time.Second
	prof := strings.TrimSuffix(bait, `\Login Data`)
	go func() {
		time.Sleep(150 * time.Millisecond)
		os.MkdirAll(prof+`\Sessions`, 0o755)
		os.WriteFile(prof+`\Secure Preferences`, []byte("{}"), 0o644)
	}()
	e.HandleAccess(ev(1000, chromeExe, bait, 0x10000))            // delete
	e.HandleAccess(ev(1000, chromeExe, cookiesOf(bait), 0x10000)) // and the next file: same alert
	a := only(f)
	if a == nil || len(f.saved) != 1 || a.Kind != alerts.KindDecoyRetired || len(f.retired) != 1 || len(f.blocked) != 0 || len(f.suspended) != 0 {
		t.Fatalf("alert %+v, alerts %d, retired %v, blocked %v", a, len(f.saved), f.retired, f.blocked)
	}
	for _, bad := range []string{"stealer", "Possible", "wiper", "ransomware"} {
		if strings.Contains(a.Title+" "+a.Summary, bad) {
			t.Errorf("%q in %q / %q", bad, a.Title, a.Summary)
		}
	}
	if !strings.Contains(a.Summary, "for a profile you added") || !strings.Contains(a.Summary, "new fake profile") {
		t.Errorf("summary: %q", a.Summary)
	}

	// Going to delete the fake's files without making the folder a profile:
	// after the longer wait, the browser you use is cut off as usual.
	e, f, bait, _ = browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	e.takeWait = 200 * time.Millisecond
	e.HandleAccess(ev(1000, chromeExe, bait, 0x10000))
	if a := only(f); a == nil || !a.Verdict.KeepRunning || len(f.blocked) != 1 || len(f.retired) != 0 {
		t.Fatalf("not taken: %+v, blocked %v", a, f.blocked)
	}

	// A plain read isn't given the long wait.
	e, f, bait, _ = browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	e.takeWait = 5 * time.Second
	start := time.Now()
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	if time.Since(start) > 2*time.Second || !only(f).Verdict.KeepRunning {
		t.Fatalf("a read waited %v", time.Since(start))
	}
}

// The VM's timeline of Brave's own "Add profile" reaching the fake's name:
// the three files deleted at +0.09/0.17/0.24 s, the folder gone at +0.28 s,
// the window check at +0.42 s, the folder made anew as a real profile at
// +1.3 s, listed in Local State only at +10.1 s. ABA must recognise the
// folder taken from disk well before its wait ends, cut nothing, and raise
// one plain alert.
func TestProfileAddedInTheBrowserTimeline(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	prof := strings.TrimSuffix(bait, `\Login Data`)
	webData := prof + `\Web Data`
	// The fake profile on disk first: the temporary folder's path has an 8.3
	// short name in it, which paths.Key only spells out for files that exist.
	os.MkdirAll(prof+`\Network`, 0o755)
	for _, p := range []string{bait, cookiesOf(bait), webData, prof + `\Preferences`} {
		os.WriteFile(p, []byte("fake"), 0o644)
	}
	st := stateWithAll()
	st.Baits["chrome-profile"] = &config.BaitState{ID: "chrome-profile", Name: "extra profile inside your Chrome",
		Files: []config.BaitFile{{Path: bait, Audit: true}, {Path: cookiesOf(bait), Audit: true}, {Path: webData, Audit: true}}}
	e.Configure(e.cfg, st)
	start := time.Now()
	done := make(chan bool, 3)
	for i, p := range []string{bait, cookiesOf(bait), webData} {
		i, p := i, p
		go func() {
			time.Sleep(time.Duration(90+75*i) * time.Millisecond)
			e.HandleAccess(ev(1000, chromeExe, p, 0x10000))
			done <- true
		}()
	}
	go func() {
		time.Sleep(280 * time.Millisecond)
		os.RemoveAll(prof)
		time.Sleep(1020 * time.Millisecond) // +1.3 s: a real profile
		os.MkdirAll(prof+`\Network`, 0o755)
		for _, n := range []string{"Preferences", "Secure Preferences", "Extension State", "Login Data", "Web Data", `Network\Cookies`} {
			os.WriteFile(prof+`\`+n, []byte("real"), 0o644)
		}
		os.MkdirAll(prof+`\Sessions`, 0o755)
	}()
	for i := 0; i < 3; i++ {
		<-done
	}
	took := time.Since(start)
	a := only(f)
	if len(f.saved) != 1 || a == nil || a.Kind != alerts.KindDecoyRetired || len(f.blocked) != 0 || len(f.suspended) != 0 || len(f.retired) != 1 {
		t.Fatalf("alerts %d, alert %+v, blocked %v, retired %v", len(f.saved), a, f.blocked, f.retired)
	}
	if took > 4*time.Second || a.Tier != config.TierInfo || strings.Contains(a.Title+a.Summary, "stealer") {
		t.Fatalf("took %v; %s: %q / %q", took, a.Tier, a.Title, a.Summary)
	}
	if len(a.Baits) != 3 {
		t.Errorf("the three deletes in one alert: %+v", a.Baits)
	}
}

// After `aba resume` gave the browser you're using its internet back, the
// same browser going through the fake profile again (here from its network
// service, one of its own processes) is a new alert, and its internet is
// cut again: not a line added to the old one.
func TestAgainAfterResumeIsANewAlert(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	f.cmdlines[1002] = `"` + chromeExe + `" --type=utility --utility-sub-type=network.mojom.NetworkService`
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	first := only(f)
	if first == nil || !first.Verdict.KeepRunning || len(f.blocked) != 1 {
		t.Fatalf("first: %+v", first)
	}
	// `aba resume <id>`: its internet is back.
	f.state.Blocked = nil
	e.HandleAccess(ev(1002, chromeExe, bait, 1))
	if len(f.saved) != 2 || len(f.blocked) != 2 || len(f.desktop) != 2 {
		t.Fatalf("after resume: alerts %d, blocked %v, popups %d", len(f.saved), f.blocked, len(f.desktop))
	}
	for _, a := range f.saved {
		if a.ID != first.ID && (!a.Verdict.KeepRunning || a.Process.PID != 1002 || !a.Did(config.ActionBlockProgram)) {
			t.Fatalf("second: %+v", a)
		}
	}
	// While the block is still in place, the same reads do join.
	e.HandleAccess(ev(1001, chromeExe, cookiesOf(bait), 1))
	if len(f.saved) != 2 {
		t.Fatalf("a read while it's still cut off made a third alert")
	}
}

// The title and reasons say what gave the browser away, and never that it
// was "hidden" or not the one you use when that isn't what ABA saw.
func TestBrowserAlertSaysWhatGaveItAway(t *testing.T) {
	cmdExe := `C:\Windows\System32\cmd.exe`
	for _, tc := range []struct {
		name, title string
		starter     uint32
		image       string
		mod         func(*procinfo.BrowserInstance)
		visible     bool
	}{
		{"created suspended", "a Chrome started suspended by ghost.exe", 900, ghostExe, suspended, false},
		{"hidden", "a Chrome started hidden by ghost.exe", 900, ghostExe, func(b *procinfo.BrowserInstance) { b.Hidden = []string{"it was told to keep its window hidden"} }, false},
		{"no window", "a Chrome with no window on your screen", 4410, explorerExe, nil, false},
		{"started from cmd.exe", "a Chrome started by cmd.exe", 905, cmdExe, nil, true},
	} {
		e, f, bait, b := browserUser(t, "balanced", tc.starter, tc.image, tc.mod)
		signed(f, cmdExe, "Microsoft Windows")
		f.parents[b.Main] = []procinfo.Ancestor{{PID: tc.starter, Image: tc.image, CreateTime: 1}}
		f.visible[1000] = tc.visible
		e.HandleAccess(ev(1000, chromeExe, bait, 1))
		a := only(f)
		if a == nil || !a.Did(config.ActionFreeze) || !strings.Contains(a.Title, tc.title) {
			t.Fatalf("%s: %+v", tc.name, a)
		}
		all := a.Title + " " + strings.Join(a.Verdict.Reasons, " ")
		for _, wrong := range []string{"hidden copy", "windows you use"} {
			if strings.Contains(all, wrong) {
				t.Errorf("%s: %q in %s", tc.name, wrong, all)
			}
		}
		if tc.name != "hidden" && strings.Contains(a.Title, "hidden") {
			t.Errorf("%s: %q", tc.name, a.Title)
		}
	}
}

// Caught inside its open, then resumed by you: the next read the event log
// reports is a new alert and a new freeze, not a line in the old one.
func TestInstantCatchResumedThenReadsAgain(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	img := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	f.images[100] = img
	if !e.DecideInstant(100, desktopBait) {
		t.Fatal("not frozen inside the open")
	}
	e.HandleOpen(100, desktopBait, time.Now(), []uint32{100})
	f.state.Frozen, f.state.Blocked = nil, nil // `aba resume <id>`
	e.HandleAccess(ev(100, img, discordBait, 1))
	if len(f.saved) != 2 || len(f.suspended) != 1 {
		t.Fatalf("alerts %d, suspended %v", len(f.saved), f.suspended)
	}
}

// One of the browser's own processes (its network service) opening the fake
// profile is handled like the main process: the whole instance is judged,
// from its main process.
func TestABrowsersChildIsHandledLikeItsMain(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 4410, explorerExe, nil)
	f.visible[1000] = true
	e.HandleAccess(ev(1002, chromeExe, bait, 1))
	if a := only(f); a == nil || !a.Verdict.KeepRunning || len(f.blocked) != 1 || f.asked != 1 {
		t.Fatalf("network service: %+v, blocked %v, window checks %d", a, f.blocked, f.asked)
	}
	e, f, bait, _ = browserUser(t, "balanced", 900, ghostExe, suspended)
	e.HandleAccess(ev(1002, chromeExe, bait, 1))
	if len(f.suspended) == 0 || f.suspended[0] != 1000 {
		t.Fatalf("frozen from its main process: %v", f.suspended)
	}
}

// The VM sequence with the real tool (-k -v chrome) while your Chrome and
// Edge were open: earlier catches of its Chrome and Brave copies, Edge's
// routine read of the password list, then the tool's next Chrome copy. Only
// that copy and what started it are frozen; only the starter is cut off;
// Edge and chrome.exe never.
func TestAStealersBrowserIsFrozenAloneAfterOtherCatches(t *testing.T) {
	e, f, bait, braveBait := threeBrowsers(t)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	e.HandleAccess(ev(2000, braveExe, braveBait, 1))
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	second := &procinfo.BrowserInstance{Main: 5000, MainCreate: 1, Image: chromeExe, PIDs: []uint32{5000}, CreatedSuspended: true,
		Starter: 902, StarterImage: ghostExe, StarterCreate: 1}
	f.browsers[5000], f.images[5000], f.images[902] = second, chromeExe, ghostExe
	f.parents[5000] = []procinfo.Ancestor{{PID: 902, Image: ghostExe, CreateTime: 1}}
	e.HandleAccess(ev(5000, chromeExe, cookiesOf(bait), 1))
	var a *alerts.Alert
	for _, x := range f.saved {
		if x.Process.PID == 5000 {
			a = x
		}
	}
	if a == nil || !a.Verdict.Host || len(a.Verdict.Swept) > 0 {
		t.Fatalf("the tool's next copy: %+v", a)
	}
	for _, fr := range f.state.Frozen {
		if fr.AlertID == a.ID && fr.PID != 5000 && fr.PID != 5001 && fr.PID != 902 {
			t.Fatalf("frozen with it: %+v", f.state.Frozen)
		}
	}
	if hasP(f.suspended, 3000) {
		t.Fatal("Edge frozen")
	}
	for _, b := range f.blocked {
		if b == chromeExe || b == edgeExe || b == braveExe {
			t.Fatalf("blocked %v", f.blocked)
		}
	}
}

// The same, then something put into the Chrome you're using goes through the
// fake profile: left running, cut off, not frozen as part of a team.
func TestTheBrowserYoureUsingAfterOtherCatches(t *testing.T) {
	e, f, bait, braveBait := threeBrowsers(t)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	e.HandleAccess(ev(2000, braveExe, braveBait, 1))
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	yours := &procinfo.BrowserInstance{Main: 6000, MainCreate: 1, Image: chromeExe, PIDs: []uint32{6000, 6001}, Starter: 4410, StarterImage: explorerExe, StarterCreate: 1}
	f.browsers[6000], f.browsers[6001], f.images[6000], f.images[6001] = yours, yours, chromeExe, chromeExe
	f.visible[6000] = true
	e.HandleAccess(ev(6001, chromeExe, bait, 1))
	var a *alerts.Alert
	for _, x := range f.saved {
		if x.Process.PID == 6001 {
			a = x
		}
	}
	if a == nil || !a.Verdict.KeepRunning || hasP(f.suspended, 6000) || hasP(f.suspended, 6001) || hasP(f.suspended, 3000) {
		t.Fatalf("your Chrome: %+v, suspended %v", a, f.suspended)
	}
}

// Your Edge reads the password list on its own, then code put into it goes
// through its fake profile: still the browser you're using (its own fake
// profile never counts toward a sweep). Only reads of two more apps' data
// make it a sweep.
func TestTheBrowserYoureUsingAndASweep(t *testing.T) {
	e, f, bait, _ := threeBrowsers(t)
	_ = bait
	edgeBait := addEdge(t, e)
	yours := &procinfo.BrowserInstance{Main: 3000, MainCreate: 1, Image: edgeExe, PIDs: []uint32{3000}, Starter: 4410, StarterImage: explorerExe, StarterCreate: 1}
	f.browsers[3000] = yours
	f.visible[3000] = true
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	e.HandleAccess(ev(3000, edgeExe, edgeBait, 1))
	kept := false
	for _, a := range f.saved {
		kept = kept || (a.Verdict.KeepRunning && a.Process.PID == 3000 && a.Did(config.ActionBlockProgram))
	}
	if !kept {
		t.Fatal("its fake profile read after a quiet read of the password list must still be judged by the host policy (left running, cut off)")
	}
	e.HandleAccess(ev(3000, edgeExe, discordBait, 1))
	if hasP(f.suspended, 3000) {
		t.Fatalf("your Edge frozen for the password list, its fake profile and one more app: %v", f.suspended)
	}
	e.HandleAccess(ev(3000, edgeExe, awsBait, 1))
	if !hasP(f.suspended, 3000) {
		t.Fatal("three other apps' data: that's a sweep, whatever it is")
	}
}

// threeBrowsers: Chrome (1000, a stealer's copy started by ghost.exe), Brave
// (2000, the same) and your Edge (3000), each with a fake profile.
func threeBrowsers(t *testing.T) (*Engine, *fakeOps, string, string) {
	t.Helper()
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	e.cfg.InstantFreeze = true
	braveUD := strings.Replace(strings.TrimSuffix(bait, `Profile 23\Login Data`), `Google\Chrome`, `BraveSoftware\Brave-Browser`, 1)
	os.MkdirAll(braveUD, 0o755)
	os.WriteFile(braveUD+"Local State", []byte(`{"profile":{"info_cache":{"Default":{}}}}`), 0o644)
	e.cfg.User.Embedded["brave-profile"] = "Profile 13"
	braveBait := braveUD + `Profile 13\Network\Cookies`
	st := stateWithAll()
	st.Baits["chrome-profile"] = &config.BaitState{ID: "chrome-profile", Name: "extra profile inside your Chrome",
		Files: []config.BaitFile{{Path: bait, Audit: true}, {Path: cookiesOf(bait), Audit: true}}}
	st.Baits["brave-profile"] = &config.BaitState{ID: "brave-profile", Name: "extra profile inside your Brave", Files: []config.BaitFile{{Path: braveBait, Audit: true}}}
	e.Configure(e.cfg, st)
	brave := &procinfo.BrowserInstance{Main: 2000, MainCreate: 1, Image: braveExe, PIDs: []uint32{2000}, CreatedSuspended: true,
		Starter: 900, StarterImage: ghostExe, StarterCreate: 1}
	f.browsers[2000], f.images[2000] = brave, braveExe
	signed(f, braveExe, "Brave Software Inc")
	f.images[3000] = edgeExe
	signed(f, edgeExe, "Microsoft Corporation")
	return e, f, bait, braveBait
}

// addEdge gives Edge a fake profile too, and returns its bait.
func addEdge(t *testing.T, e *Engine) string {
	t.Helper()
	ud := e.cfg.User.LocalAppData + `\Microsoft\Edge\User Data\`
	os.MkdirAll(ud, 0o755)
	os.WriteFile(ud+"Local State", []byte(`{"profile":{"info_cache":{"Default":{}}}}`), 0o644)
	e.cfg.User.Embedded["edge-profile"] = "Profile 17"
	b := ud + `Profile 17\Login Data`
	st := stateWithAll()
	st.Baits["edge-profile"] = &config.BaitState{ID: "edge-profile", Name: "extra profile inside your Edge", Files: []config.BaitFile{{Path: b, Audit: true}}}
	e.Configure(e.cfg, st)
	return b
}

const (
	braveExe = `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`
	edgeExe  = `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
)

// The VM run with all three browsers open: the tool's Chrome and Brave each
// went through their fake profile, then the person's own Edge read the
// password-list bait as it does on every start (only "info": signed,
// installed). Edge used to be frozen as the last of "3 programs together"
// reading 3 apps' data. A browser the host policy dealt with is a closed
// case: it doesn't make a stranger part of a team.
func TestHostReadsDontMakeAStrangerATeammate(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	e.cfg.InstantFreeze = true
	// Brave too, with its own fake profile, and its own copy run by the tool.
	braveUD := strings.Replace(strings.TrimSuffix(bait, `Profile 23\Login Data`), `Google\Chrome`, `BraveSoftware\Brave-Browser`, 1)
	os.MkdirAll(braveUD, 0o755)
	os.WriteFile(braveUD+"Local State", []byte(`{"profile":{"info_cache":{"Default":{}}}}`), 0o644)
	e.cfg.User.Embedded["brave-profile"] = "Profile 13"
	braveBait := braveUD + `Profile 13\Network\Cookies`
	st := stateWithAll()
	st.Baits["chrome-profile"] = &config.BaitState{ID: "chrome-profile", Name: "extra profile inside your Chrome", Files: []config.BaitFile{{Path: bait, Audit: true}}}
	st.Baits["brave-profile"] = &config.BaitState{ID: "brave-profile", Name: "extra profile inside your Brave", Files: []config.BaitFile{{Path: braveBait, Audit: true}}}
	e.Configure(e.cfg, st)
	brave := &procinfo.BrowserInstance{Main: 2000, MainCreate: 1, Image: braveExe, PIDs: []uint32{2000}, CreatedSuspended: true,
		Starter: 900, StarterImage: ghostExe, StarterCreate: 1}
	f.browsers[2000], f.images[2000] = brave, braveExe
	signed(f, braveExe, "Brave Software Inc")
	f.images[3000] = edgeExe
	signed(f, edgeExe, "Microsoft Corporation")

	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	e.HandleAccess(ev(2000, braveExe, braveBait, 1))
	if ok, why := e.DecideInstantOpWhy(3000, desktopBait, 0); ok {
		t.Fatalf("the person's Edge frozen inside its open: %s", why)
	}
	e.HandleAccess(ev(3000, edgeExe, desktopBait, 1))
	for _, a := range f.saved {
		if a.Process.PID == 3000 && (a.Tier == config.TierCritical || len(a.Verdict.Swept) > 0) {
			t.Fatalf("Edge convicted by the browsers' reads: %+v", a)
		}
	}
	if hasP(f.suspended, 3000) || hasP(frozenPIDs(f), 3000) {
		t.Fatalf("Edge frozen: %v", f.suspended)
	}
}

// A genuine browser frozen for something else (a sweep it was part of) reads
// its own profiles all day: the autopsy doesn't count those as taken. A
// browser a stealer started and ran its code in is the stealer's: what it
// opened counts.
func TestAutopsyOfAGenuineBrowserLeavesItsOwnDataOut(t *testing.T) {
	e, f := setup("balanced")
	f.images[3000] = edgeExe
	signed(f, edgeExe, "Microsoft Corporation")
	for _, b := range []string{desktopBait, discordBait, awsBait} {
		e.HandleAccess(ev(3000, edgeExe, b, 1))
	}
	c := waitCase(t, f)
	if c.Own[3000] != "edge-profile" {
		t.Fatalf("Edge's own data: %v", c.Own)
	}

	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	e.HandleAccess(ev(1000, chromeExe, bait, 1))
	if c := waitCase(t, f); len(c.Own) != 0 {
		t.Fatalf("the stealer's copy of Chrome: %v", c.Own)
	}
}

func waitCase(t *testing.T, f *fakeOps) autopsy.Case {
	t.Helper()
	for i := 0; i < 200; i++ {
		f.mu.Lock()
		n := len(f.cases)
		var c autopsy.Case
		if n > 0 {
			c = f.cases[n-1]
		}
		f.mu.Unlock()
		if n > 0 {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no autopsy")
	return autopsy.Case{}
}

// While the open is still paused: the one genuine browser among the paused
// programs that was created suspended is named, so it never gets a byte.
func TestHostSuspect(t *testing.T) {
	e, f, bait, _ := browserUser(t, "balanced", 900, ghostExe, suspended)
	f.images[555] = `C:\Windows\System32\notepad.exe`
	if p := e.HostSuspect(bait, []uint32{555, 1000}); p != 1000 {
		t.Fatalf("suspect: %d", p)
	}
	if p := e.HostSuspect(desktopBait, []uint32{555, 1000}); p != 0 {
		t.Fatalf("not a fake profile: %d", p)
	}
	// A look-alike elsewhere isn't the browser.
	e, f, bait, _ = browserUser(t, "balanced", 900, ghostExe, suspended)
	for _, p := range []uint32{1000, 1001, 1002} {
		f.images[p] = `C:\Users\bob\Downloads\chrome.exe`
	}
	if p := e.HostSuspect(bait, []uint32{1000}); p != 0 {
		t.Fatalf("a chrome.exe outside Chrome's folder: %d", p)
	}
	// The browser you're using is never named here.
	e, f, bait, _ = browserUser(t, "balanced", 4410, explorerExe, nil)
	if p := e.HostSuspect(bait, []uint32{1000, 1001}); p != 0 {
		t.Fatalf("a browser that wasn't created suspended: %d", p)
	}
	// Two at once: don't guess.
	e, f, bait, _ = browserUser(t, "balanced", 900, ghostExe, suspended)
	other := &procinfo.BrowserInstance{Main: 2000, Image: chromeExe, PIDs: []uint32{2000}, CreatedSuspended: true, StarterGone: true}
	f.browsers[2000], f.images[2000] = other, chromeExe
	if p := e.HostSuspect(bait, []uint32{1000, 2000}); p != 0 {
		t.Fatalf("two candidates: %d", p)
	}
}
