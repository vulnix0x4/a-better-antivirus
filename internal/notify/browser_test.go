package notify

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

const keptSummary = "Chrome opened a fake profile that only a stealer would open: something is running inside the Chrome you're using (an add-on, or code a stealer put into it). ABA left it running, since it's the browser you're using, and cut the internet of every Chrome window instead"

func browserAlert(v classify.Verdict, summary string, acts ...config.Action) *alerts.Alert {
	a := &alerts.Alert{ID: "20261123-101500-ab12", Tier: config.TierCritical, Kind: alerts.KindRead, Verdict: v, Summary: summary,
		Baits:   []alerts.BaitHit{{Name: "extra profile inside your Chrome", Path: `C:\Users\you\AppData\Local\Google\Chrome\User Data\Profile 23\Login Data`, Access: "read"}},
		Process: &alerts.Process{PID: 4242, Image: `C:\Program Files\Google\Chrome\Application\chrome.exe`}}
	for _, act := range acts {
		a.AddAction(act, nil, "")
	}
	return a
}

// The browser you're using, left running with its internet cut: Yes gives
// it back (`aba resume`, nothing trusted), No keeps it cut. Never "trust",
// and "left it running" said once.
func TestPopupForTheBrowserYoureUsing(t *testing.T) {
	a := browserAlert(classify.Verdict{Host: true, KeepRunning: true}, keptSummary, config.ActionBlockProgram, config.ActionLeftRunning)
	text, flags, yes, no := browserPopup(a, Details(a))
	for _, want := range []string{"left it running", "cut the internet of every Chrome window", "Yes = Restore it now (nothing gets trusted)", "No = Keep it cut"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "left it running"); n != 1 {
		t.Errorf("\"left it running\" said %d times:\n%s", n, text)
	}
	if flags&0xF != mbYesNo || strings.Join(yes, " ") != "resume "+a.ID || no != nil || strings.Contains(strings.ToLower(text), "trust it") {
		t.Fatalf("buttons %x, yes %v, no %v:\n%s", flags, yes, no, text)
	}
	if testing.Verbose() {
		t.Log("\n" + text)
	}

	// Alert only: nothing was cut, nothing to answer.
	a = browserAlert(classify.Verdict{Host: true, KeepRunning: true}, "Chrome opened a fake profile. ABA left it running: it's the browser you're using")
	if text, flags, yes, _ := browserPopup(a, Details(a)); flags&0xF != mbOK || yes != nil || strings.Contains(text, "cut the internet") {
		t.Fatalf("alert only:\n%s", text)
	}
}

// A browser a stealer started, frozen: kill it, or unfreeze it once. What
// was frozen and cut off is said as it is: the browser and what started it,
// and only the starter's internet.
func TestPopupForAFrozenBrowser(t *testing.T) {
	a := browserAlert(classify.Verdict{Host: true}, "Chrome was started suspended by ghost.exe")
	a.AddAction(config.ActionFreeze, nil, "4 process(es) frozen: that whole Chrome (from its main process, pid 9120) and what started it: ghost.exe (pid 9088), the moment it opened the bait")
	a.AddAction(config.ActionBlockProgram, nil, config.StarterBlocked+`C:\Users\you\Downloads\ghost.exe`)
	text, flags, yes, no := browserPopup(a, Details(a))
	if flags&0xF != mbYesNoCancel || strings.Join(yes, " ") != "kill "+a.ID || strings.Join(no, " ") != "resume "+a.ID {
		t.Fatalf("buttons %x, yes %v, no %v", flags, yes, no)
	}
	for _, want := range []string{"ABA froze that Chrome", "nothing gets trusted", "✓ Froze that whole Chrome (from its main process, pid 9120) and what started it: ghost.exe",
		"✓ Cut the internet of what started it (ghost.exe)"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	for _, wrong := range []string{"process(es) it started", "✓ Cut its internet", "you're using"} {
		if strings.Contains(text, wrong) {
			t.Errorf("%q in:\n%s", wrong, text)
		}
	}
	if testing.Verbose() {
		t.Log("\n" + text)
	}

	// Gone before ABA could look: nothing to answer.
	a = browserAlert(classify.Verdict{Host: true}, "Chrome opened a fake profile and had already exited")
	a.Process.Exited = true
	if text, flags, yes, _ := browserPopup(a, Details(a)); flags&0xF != mbOK || yes != nil || !strings.Contains(text, "left to stop") {
		t.Fatalf("gone:\n%s", text)
	}
}
