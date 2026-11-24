package engine

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
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
	if !strings.Contains(a.Title, "inside Chrome") {
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
