package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// chromeUser sets the engine up for someone who really uses Chrome, with
// ABA's fake profile ("Profile 23") inside Chrome's data. It returns the
// bait's path and Chrome's Local State file.
func chromeUser(t *testing.T, e *Engine) (bait, localState string) {
	t.Helper()
	local := filepath.Join(t.TempDir(), "AppData", "Local")
	ud := filepath.Join(local, `Google\Chrome\User Data`)
	os.MkdirAll(ud, 0o755)
	localState = filepath.Join(ud, "Local State")
	os.WriteFile(localState, []byte(`{"profile":{"info_cache":{"Default":{}}}}`), 0o644)
	e.cfg.User.LocalAppData = local
	e.cfg.User.Embedded = map[string]string{"chrome-profile": "Profile 23"}
	bait = filepath.Join(ud, "Profile 23", "Login Data")
	st := stateWithAll()
	st.Baits["chrome-profile"] = &config.BaitState{ID: "chrome-profile", Name: "extra profile inside your Chrome",
		Files: []config.BaitFile{{Path: bait, Audit: true}}}
	e.Configure(e.cfg, st)
	return bait, localState
}

// The bypass this bait is for: a stealer that checks the browser is really
// installed before touching its data, so that it never opens a decoy. Chrome
// *is* installed here, and the fake profile sits among the real ones.
func TestFakeProfileInsideTheRealBrowser(t *testing.T) {
	e, f := setup("balanced")
	bait, _ := chromeUser(t, e)
	e.HandleAccess(ev(100, `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`, bait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || a.Baits[0].Name != "extra profile inside your Chrome" {
		t.Fatalf("a stealer going through Chrome's profiles: %+v", a)
	}
}

// Chrome itself only opens the profiles it knows. The real chrome.exe
// reading the fake one is therefore not "the app reading its own data" (which
// would retire the bait): it's something inside Chrome going through its
// profiles. Only once Chrome has taken the folder as a profile is it Chrome's.
func TestTheBrowserReadingAProfileItDoesntKnow(t *testing.T) {
	e, f := setup("balanced")
	bait, localState := chromeUser(t, e)
	chrome := `C:\Program Files\Google\Chrome\Application\chrome.exe`
	signed(f, chrome, "Google LLC")
	e.HandleAccess(ev(200, chrome, bait, 1))
	a := only(f)
	if a == nil || len(f.retired) != 0 || a.Kind != alerts.KindRead || a.Tier != config.TierWarn || !strings.Contains(a.Summary, "isn't one of its own") {
		t.Fatalf("chrome.exe opening a profile Chrome doesn't know: %+v retired=%v", a, f.retired)
	}
	if len(f.desktop) != 1 {
		t.Fatal("that deserves a popup, not a quiet note")
	}
	_ = localState
	// You created profiles until Chrome reached that folder and adopted it.
	e2, f2 := setup("balanced")
	bait2, ls2 := chromeUser(t, e2)
	os.WriteFile(ls2, []byte(`{"profile":{"info_cache":{"Default":{},"Profile 23":{"name":"Work"}}}}`), 0o644)
	signed(f2, chrome, "Google LLC")
	e2.HandleAccess(ev(300, chrome, bait2, 1))
	if a := only(f2); a == nil || len(f2.retired) != 1 || a.Kind != alerts.KindDecoyRetired {
		t.Fatalf("Chrome using the folder as its own profile should retire the bait: %+v retired=%v", a, f2.retired)
	}
	// A copy of chrome.exe somewhere else is never the owner.
	e3, f3 := setup("balanced")
	bait3, ls3 := chromeUser(t, e3)
	os.WriteFile(ls3, []byte(`{"profile":{"info_cache":{"Default":{},"Profile 23":{}}}}`), 0o644)
	elsewhere := `C:\Users\bob\Downloads\c\chrome.exe`
	signed(f3, elsewhere, "Google LLC")
	e3.HandleAccess(ev(400, elsewhere, bait3, 1))
	if len(f3.retired) != 0 {
		t.Fatal("a copy of the genuine chrome.exe outside its install folder retired the bait")
	}
}

// The fake profile counts as an app of its own in a sweep, so the two
// browsers nearly everyone has are already two of the three.
func TestBrowserProfilesCountInASweep(t *testing.T) {
	e, f := setup("balanced")
	bait, _ := chromeUser(t, e)
	np := `C:\Windows\System32\notepad.exe` // stands for any program that looks harmless by itself
	signed(f, np, "Microsoft Windows")
	for _, b := range []string{bait, discordBait, desktopBait} {
		e.HandleAccess(ev(500, np, b, 1))
	}
	if a := lastAlert(f); a.Tier != config.TierCritical || len(a.Verdict.Swept) != 3 {
		t.Fatalf("Chrome's fake profile + Discord + your files: %+v", a)
	}
}
