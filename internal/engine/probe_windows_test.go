package engine

import (
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

const (
	vivaldiLS  = `C:\Users\bob\AppData\Local\Vivaldi\User Data\Local State`
	operaLS    = `C:\Users\bob\AppData\Roaming\Opera Software\Opera Stable\Local State`
	yandexLS   = `C:\Users\bob\AppData\Local\Yandex\YandexBrowser\User Data\Local State`
	vivaldiLD  = `C:\Users\bob\AppData\Local\Vivaldi\User Data\Default\Login Data`
	operaLD    = `C:\Users\bob\AppData\Roaming\Opera Software\Opera Stable\Login Data`
	yandexLD   = `C:\Users\bob\AppData\Local\Yandex\YandexBrowser\User Data\Default\Ya Passman Data`
	braveDecoy = `C:\Users\bob\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State`
	braveMM    = `C:\Users\bob\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log`
)

// fakeBrowsers is setup with the fake Vivaldi, Opera, Yandex and Brave
// profiles (MetaMask inside the fake Brave), and the real Brave installed.
func fakeBrowsers(t *testing.T) (*Engine, *fakeOps) {
	t.Helper()
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	st := stateWithAll()
	for id, files := range map[string][]string{"vivaldi": {vivaldiLS, vivaldiLD}, "opera": {operaLS, operaLD}, "yandex": {yandexLS, yandexLD},
		"brave": {braveDecoy}, "metamask": {braveMM}} {
		bs := &config.BaitState{ID: id, Name: id + " profile"}
		for _, p := range files {
			bs.Files = append(bs.Files, config.BaitFile{Path: p, Audit: true})
		}
		st.Baits[id] = bs
	}
	e.Configure(e.cfg, st)
	f.images[4000] = braveExe
	signed(f, braveExe, "Brave Software Inc")
	return e, f
}

// The cost test's VM: Brave, installed the normal way, opened the fake
// Vivaldi, Opera and Yandex `Local State` files on its first start (as it
// does on every start, looking for browsers to import from), and was frozen
// as a stealer sweeping three apps' data, its internet cut.
func TestBrowserImportProbeIsNotASweep(t *testing.T) {
	e, f := fakeBrowsers(t)
	for _, p := range []string{vivaldiLS, operaLS, yandexLS} {
		if ok, why := e.DecideInstantWhy(4000, p); ok {
			t.Fatalf("Brave opening %s was frozen: %s", p, why)
		}
		e.HandleAccess(ev(4000, braveExe, p, 1))
	}
	for _, a := range f.saved {
		if a.Tier == config.TierCritical || len(a.Actions) > 0 {
			t.Fatalf("an import probe was handled as a stealer: %+v", a)
		}
	}
	if len(f.suspended) != 0 || len(f.blocked) != 0 {
		t.Fatalf("frozen %v, blocked %v", f.suspended, f.blocked)
	}

	// The same Brave going on to the passwords of three browsers is a sweep,
	// stopped inside the open of the third.
	if e.DecideInstant(4000, vivaldiLD) || e.DecideInstant(4000, operaLD) {
		t.Fatal("one or two apps' data is no sweep yet")
	}
	if !e.DecideInstant(4000, yandexLD) {
		t.Fatal("a third browser's passwords: a sweep, whatever program it is")
	}
}

// A program that isn't a genuine browser opening three browsers' `Local
// State` is a sweep as before: that's where a stealer gets each browser's key.
func TestLocalStateSweepByAnythingElse(t *testing.T) {
	e, f := fakeBrowsers(t)
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.images[200] = code
	signed(f, code, "Microsoft Corporation")
	if e.DecideInstant(200, vivaldiLS) || e.DecideInstant(200, operaLS) {
		t.Fatal("one or two apps' data is no sweep yet")
	}
	if !e.DecideInstant(200, yandexLS) {
		t.Fatal("three browsers' Local State by a program that isn't a browser: a sweep")
	}
	// A copy of brave.exe outside where Brave installs isn't the genuine browser.
	fake := `C:\Users\bob\AppData\Local\Temp\x\brave.exe`
	f.images[201] = fake
	signed(f, fake, "Brave Software Inc")
	if !(e.DecideInstant(201, vivaldiLS) || e.DecideInstant(201, operaLS) || e.DecideInstant(201, yandexLS)) {
		t.Fatal("brave.exe run from Temp is not the genuine browser")
	}
}

// The real Brave moved into the fake Brave profile (ABA retires it): its
// own reads and writes there, MetaMask's files inside it included, aren't
// counted toward a sweep, and a write to them isn't ransomware.
func TestGenuineAppAtHomeInItsDecoy(t *testing.T) {
	e, f := fakeBrowsers(t)
	if ok, why := e.DecideInstantWhy(4000, braveMM); ok {
		t.Fatalf("Brave opening MetaMask's files in its own folder was frozen: %s", why)
	}
	e.HandleAccess(ev(4000, braveExe, braveMM, 2))
	for _, a := range f.saved {
		t.Fatalf("Brave writing its own folder made an alert: %+v", a)
	}
	e.HandleAccess(ev(4000, braveExe, braveDecoy, 1))
	e.HandleAccess(ev(4000, braveExe, vivaldiLS, 1))
	e.HandleAccess(ev(4000, braveExe, operaLS, 1))
	for _, a := range f.saved {
		if a.Tier == config.TierCritical || len(a.Verdict.Swept) > 0 {
			t.Fatalf("not a sweep: %+v", a)
		}
	}
	if len(f.retired) != 1 || len(f.desktop) != 1 {
		t.Fatalf("Brave reading its own decoy retires it, and you're told: retired %v, told %v", f.retired, f.desktop)
	}
	// The decoy waits for Brave to close; Brave started again reads it again:
	// asked to retire once more, but you aren't told twice.
	f.images[4001] = braveExe
	e.HandleAccess(ev(4001, braveExe, braveDecoy, 1))
	if len(f.retired) != 2 || len(f.desktop) != 1 {
		t.Fatalf("again: retired %v, told %v", f.retired, f.desktop)
	}
}
