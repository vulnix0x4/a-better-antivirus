package notify

import (
	"strings"
	"testing"
)

// The shared popup text names its answers "Yes = …"; on Linux they become
// buttons with those words, and the lines a plain list.
func TestButtonsFromMessageBoxText(t *testing.T) {
	text := "x was frozen.\n\nKill it?\nYes = Kill it (recommended)\nNo = It's mine: unfreeze it (this time only)\nCancel = Decide later (it stays frozen)\n\nIt isn't signed."
	body, as := buttons(text, mbYesNoCancel|mbIconError)
	var labels []string
	for _, a := range as {
		labels = append(labels, a.label)
	}
	if got := strings.Join(labels, ", "); got != "Kill it, It's mine, Decide later" {
		t.Fatalf("labels %q", got)
	}
	if as[0].id != idYes || as[1].id != idNo || as[2].id == idYes || as[2].id == idNo {
		t.Fatalf("answers %+v", as)
	}
	if strings.Contains(body, "Yes =") || !strings.Contains(body, "• It's mine: unfreeze it (this time only)") {
		t.Fatalf("body %q", body)
	}
	if _, as := buttons("just this", mbOK|mbIconInfo); len(as) != 0 {
		t.Fatalf("an OK box has no buttons: %+v", as)
	}
	_, as = buttons("Restore?\nYes = Restore the internet now (only if you're sure)\nNo = Keep it isolated", mbYesNo|mbIconError)
	if as[0].label != "Restore the internet now" || as[1].label != "Keep it isolated" {
		t.Fatalf("labels %+v", as)
	}
}
