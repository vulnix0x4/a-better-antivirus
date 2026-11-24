package notify

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

func browserAlert(v classify.Verdict, acts ...config.Action) *alerts.Alert {
	a := &alerts.Alert{ID: "20261123-101500-ab12", Tier: config.TierCritical, Kind: alerts.KindRead, Verdict: v,
		Summary: "Chrome opened a fake profile",
		Baits:   []alerts.BaitHit{{Name: "extra profile inside your Chrome", Path: `C:\Users\you\AppData\Local\Google\Chrome\User Data\Profile 23\Login Data`, Access: "read"}},
		Process: &alerts.Process{PID: 4242, Image: `C:\Program Files\Google\Chrome\Application\chrome.exe`}}
	for _, act := range acts {
		a.AddAction(act, nil, "")
	}
	return a
}

// The browser you're using, left running with its internet cut: Yes gives
// it back (`aba resume`, nothing trusted), No keeps it cut. Never "trust".
func TestPopupForTheBrowserYoureUsing(t *testing.T) {
	a := browserAlert(classify.Verdict{Host: true, KeepRunning: true}, config.ActionBlockProgram, config.ActionLeftRunning)
	text, flags, yes, no := browserPopup(a, Details(a))
	for _, want := range []string{"left it running", "cut the internet of every Chrome window", "Yes = Restore it now (nothing gets trusted)", "No = Keep it cut", "Left it running"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if flags&0xF != mbYesNo || strings.Join(yes, " ") != "resume "+a.ID || no != nil || strings.Contains(strings.ToLower(text), "trust it") {
		t.Fatalf("buttons %x, yes %v, no %v:\n%s", flags, yes, no, text)
	}
	if testing.Verbose() {
		t.Log("\n" + text)
	}

	// Alert only: nothing was cut, nothing to answer.
	a = browserAlert(classify.Verdict{Host: true, KeepRunning: true})
	if text, flags, yes, _ := browserPopup(a, Details(a)); flags&0xF != mbOK || yes != nil || strings.Contains(text, "cut the internet") {
		t.Fatalf("alert only:\n%s", text)
	}
}

// A browser a stealer started, frozen: kill it, or unfreeze it once.
func TestPopupForAFrozenBrowser(t *testing.T) {
	a := browserAlert(classify.Verdict{Host: true}, config.ActionFreeze, config.ActionBlockProgram)
	text, flags, yes, no := browserPopup(a, Details(a))
	if flags&0xF != mbYesNoCancel || strings.Join(yes, " ") != "kill "+a.ID || strings.Join(no, " ") != "resume "+a.ID {
		t.Fatalf("buttons %x, yes %v, no %v", flags, yes, no)
	}
	for _, want := range []string{"ABA froze that Chrome", "It isn't the Chrome you're using", "nothing gets trusted"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}

	// Gone before ABA could look: nothing to answer.
	a = browserAlert(classify.Verdict{Host: true})
	a.Process.Exited = true
	if text, flags, yes, _ := browserPopup(a, Details(a)); flags&0xF != mbOK || yes != nil || !strings.Contains(text, "left to stop") {
		t.Fatalf("gone:\n%s", text)
	}
}
