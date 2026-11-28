package notify

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/report"
)

func autopsied(sent string) *alerts.Alert {
	return &alerts.Alert{ID: "20261126-180431-2962", Process: &alerts.Process{PID: 1, Image: "Umbral.exe"},
		Autopsy: &alerts.Autopsy{Answer: alerts.AnswerRead, Sent: sent,
			Headline: "It opened your Discord token store and then connected to discord.com, so assume it was sent.",
			Summary:  []string{"Your Discord token store: 000005.ldb at 18:04:31."},
			Steps:    []string{"Change your Discord password."}}}
}

// The autopsy popup has a "Show full report" button that opens the report
// of the very alert it shows; Close opens nothing.
func TestAutopsyPopupOpensTheFullReport(t *testing.T) {
	defer func(a func(string, string, string, uint32) bool, s func(*alerts.Alert) error) { ask, showReport = a, s }(ask, showReport)
	for _, click := range []bool{true, false} {
		var title, headline, text string
		var icon uint32
		ask = func(ti, h, tx string, ic uint32) bool { title, headline, text, icon = ti, h, tx, ic; return click }
		var shown *alerts.Alert
		showReport = func(a *alerts.Alert) error { shown = a; return nil }
		a := autopsied(alerts.SentSome)
		ShowAutopsy(a)
		if headline != a.Autopsy.Headline || !strings.Contains(title, "Umbral.exe") || icon != mbIconError {
			t.Errorf("popup: title %q, headline %q, icon %#x", title, headline, icon)
		}
		for _, want := range []string{"000005.ldb", "1. Change your Discord password.", "The full report shows everything", report.Where()} {
			if !strings.Contains(text, want) {
				t.Errorf("popup text lacks %q:\n%s", want, text)
			}
		}
		if strings.Contains(text, "aba autopsy") {
			t.Errorf("the popup still sends people to a terminal command:\n%s", text)
		}
		if click && shown != a {
			t.Error("Show full report didn't open this alert's report")
		}
		if !click && shown != nil {
			t.Error("Close opened the report")
		}
	}
	// Stopped before it sent anything: a warning, not an error.
	var icon uint32
	ask = func(_, _, _ string, ic uint32) bool { icon = ic; return false }
	ShowAutopsy(autopsied(alerts.SentNothing))
	if icon != mbIconWarning {
		t.Errorf("nothing sent: icon %#x, want a warning", icon)
	}
	// No autopsy, no popup.
	ask = func(_, _, _ string, _ uint32) bool { t.Error("asked without an autopsy"); return false }
	ShowAutopsy(&alerts.Alert{ID: "x"})
}
