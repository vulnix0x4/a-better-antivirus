package notify

// What a desktop alert says and what each answer does is the same everywhere
// (this file). Putting a notification and a question on the screen, and
// running aba with administrator rights when the answer needs it, is up to
// the operating system: desktop_<os>.go.

import (
	"fmt"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/report"
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
)

// Envelope is what the service hands the popup process on its standard input
// (the alert files are for administrators only; the popup runs as you).
type Envelope struct {
	Alert         *alerts.Alert `json:"alert,omitempty"`
	LearningEnded bool          `json:"learningEnded,omitempty"`
	Trusted       int           `json:"trusted,omitempty"` // programs on the trust list
	// Autopsy: show what the autopsy of the alert's program found (it read
	// real data), not the alert itself.
	Autopsy bool `json:"autopsy,omitempty"`
	// ToastOnly: only a notification (Alert.Title and Summary); the desktop
	// app shows the rest. The alert carries nothing else (see ToastAlert).
	ToastOnly bool `json:"toastOnly,omitempty"`
}

// ToastAlert is what a toast needs of a: no paths, no program details, no
// autopsy. (The notify command runs as the person, and reads it from a
// pipe anything running as them could watch.)
func ToastAlert(a *alerts.Alert) *alerts.Alert {
	return &alerts.Alert{ID: a.ID, Time: a.Time, Kind: a.Kind, Tier: a.Tier, Title: a.Title, Summary: a.Summary,
		Test: a.Test, Status: a.Status}
}

// ShowAutopsy tells the person what the autopsy of a caught program found:
// that it had read real data, whether any of it left the PC, and what to do
// about it. Its "Show full report" button opens the whole report in the
// browser (package report), from the alert this popup already holds: the
// report files themselves are for administrators only.
func ShowAutopsy(a *alerts.Alert) {
	ap := a.Autopsy
	if ap == nil {
		return
	}
	title := "ABA: what " + a.ExeName() + " had already opened"
	icon := uint32(mbIconError)
	if ap.Sent == alerts.SentNothing {
		title, icon = "ABA: "+a.ExeName()+" was stopped before it sent anything", mbIconWarning
	}
	if !ask(title, ap.Headline, autopsyText(a), icon) {
		return
	}
	if err := showReport(a); err != nil {
		messageBox("ABA: the full report didn't open", "ABA couldn't open the report in your web browser ("+err.Error()+").\n\nTo see it: "+report.Where()+".", mbOK|mbIconWarning)
	}
}

// autopsyText is what the autopsy popup says under its headline.
func autopsyText(a *alerts.Alert) string {
	ap := a.Autopsy
	var b strings.Builder
	for i, l := range ap.Summary {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(l)
	}
	if len(ap.Steps) > 0 {
		b.WriteString("\n\nFrom another device (your phone), now:")
		for i, st := range ap.Steps {
			fmt.Fprintf(&b, "\n%d. %s", i+1, st)
		}
	}
	b.WriteString("\n\nThe full report shows everything ABA found: what it opened, where it sent it, what it left behind and how to report the thief. To see it later: " + report.Where() + ".")
	return strings.TrimLeft(b.String(), "\n")
}

// ask is askReport (desktop_<os>.go), swapped in tests.
var ask = askReport

// showReport opens the alert's full report in the browser and waits until
// it has loaded (swapped in tests).
// Where the desktop app is installed, the report opens there instead (one
// administrator prompt; see openAppFor); if the app can't be started, in the
// browser after all.
var showReport = func(a *alerts.Alert) error {
	if handled, _ := openAppFor(a); handled {
		return nil
	}
	return report.Show(report.Page(a))
}

// showReportLabel is the autopsy popup's button (askReport, desktop_<os>.go).
const showReportLabel = "Show full report"

// What messageBox is asked to show (buttons and icon) and what it answers.
// (The values are Windows' own; other systems translate.)
const (
	mbOK            = 0x0
	mbYesNoCancel   = 0x3
	mbYesNo         = 0x4
	mbIconError     = 0x10
	mbIconWarning   = 0x30
	mbIconInfo      = 0x40
	mbSetForeground = 0x10000
	mbTopmost       = 0x40000
	idYes           = 6
	idNo            = 7
)

// Details renders the long form of an alert for the popup.
func Details(a *alerts.Alert) string {
	// Message boxes use a proportional font, so no column alignment: one
	// labelled line per fact, long paths on their own line.
	var b strings.Builder
	fmt.Fprintln(&b, sentence(a.Summary))
	if p := a.Process; p != nil {
		fmt.Fprintf(&b, "\nProgram: %s (pid %d)\n", a.ExeName(), p.PID)
		if p.Image != "" {
			fmt.Fprintln(&b, p.Image)
		}
		sig := p.Signature.String()
		if a.Kind == alerts.KindMiner && p.Signature.Valid {
			// A signed system program caught mining was hollowed: say so,
			// or "signed by Microsoft" reads like a false alarm.
			sig += ". The file itself is genuine: the miner is hiding inside it"
		}
		fmt.Fprintf(&b, "%s: %s\n", vouchLabel, sig)
		if p.Origin != nil {
			fmt.Fprintln(&b, p.Origin.Line(p.Image))
		}
		if len(p.Parents) > 0 && !p.Parents[0].Exited {
			fmt.Fprintf(&b, "Started by: %s\n", procBase(p.Parents[0].Image))
		}
	}
	for _, h := range a.Baits {
		fmt.Fprintf(&b, "\nIt %s: %s\n%s\n", accessVerb(h.Access), h.Name, h.Path)
	}
	for _, l := range a.Mine.Lines() {
		fmt.Fprintln(&b, l)
	}
	if len(a.Actions) > 0 {
		fmt.Fprintln(&b, "\nWhat ABA did:")
		for _, r := range a.Actions {
			if r.OK {
				fmt.Fprintf(&b, "✓ %s\n", config.Action(r.Action).Done(r.Detail))
			} else {
				fmt.Fprintf(&b, "✗ Couldn't %s: %s\n", config.Action(r.Action).Verb(), r.Detail)
			}
		}
	}
	if a.Learning {
		fmt.Fprintln(&b, "\nLearning mode: nothing was blocked. Review with `aba learn`.")
	}
	return b.String()
}

// ShowPopup displays the alert and acts on the user's choice. cli is the
// installed aba.exe used for privileged follow-ups.
func ShowPopup(a *alerts.Alert, cli string) {
	title := "ABA: " + a.Title
	body := Details(a)
	frozen := a.Did(config.ActionFreeze) && !a.Did(config.ActionKill)
	isolated := a.Did(config.ActionIsolate) || a.Did(config.ActionDisableAdapters)

	switch {
	case a.Test:
		messageBox(title, body+"\nThis was a test. Everything worked.", mbOK|mbIconInfo)
	case a.Verdict.Host || a.Verdict.KeepRunning:
		// A browser going through a fake profile: never "It's mine, trust it".
		text, flags, yes, no := browserPopup(a, body)
		switch messageBox(title, text, flags) {
		case idYes:
			if cli != "" && len(yes) > 0 {
				RunElevated(cli, yes...)
			}
		case idNo:
			if cli != "" && len(no) > 0 {
				RunElevated(cli, no...)
			}
		}
	case frozen && a.Kind == alerts.KindMiner:
		// Someone who mines on purpose did start it: unfreezing it is one
		// click, but it can't mine until the trap is off.
		text := body + "\n" + a.ExeName() + " was frozen as it tried to mine cryptocurrency.\n" +
			"Hidden miners come with cracked games, cheats and \"free\" tools. Whatever started this one may still be on this " + platform.PC + " and start it again: run a full antivirus scan.\n\n" +
			"Kill it?\n" +
			"Yes = Kill it (recommended)\n" +
			"No = It's my own miner: unfreeze it (then turn the miner trap off with `aba miners off`, or it has nowhere to mine)\n" +
			"Cancel = Decide later (it stays frozen)"
		if isolated {
			text += "\n\nYour " + platform.PC + " is isolated from the network. When it's safe, run `aba release` as admin."
		}
		switch messageBox(title, text, mbYesNoCancel|mbIconError) {
		case idYes:
			if cli != "" {
				RunElevated(cli, "kill", a.ID)
			}
		case idNo:
			if cli != "" {
				RunElevated(cli, "resume", a.ID)
			}
		}
	case frozen:
		// "Is it yours?" is the wrong question here: people who ran a cracked
		// game or a "free Nitro" tool did start it themselves. Ask whether it
		// should be reading this, and only trust signed programs in one click.
		// The question must be one where "Yes" means kill: an earlier "Did you
		// expect it to read this?" made an honest "yes" kill the program.
		oneClick := trust.OneClick(a)
		text := body + "\n" + a.ExeName() + " was frozen while reading " + baitWhat(a) + ".\n" +
			"Games, mods, cheats, cracks and \"free\" tools never need to, even ones you started yourself.\n\n" +
			"Kill it?\n" +
			"Yes = Kill it (recommended)\n"
		if oneClick {
			text += "No = It's mine: unfreeze it and trust it for this from now on\n"
		} else {
			text += "No = It's mine: unfreeze it (this time only)\n"
		}
		text += "Cancel = Decide later (it stays frozen)" + warnings(a)
		if isolated {
			text += "\n\nYour " + platform.PC + " is isolated from the network. When it's safe, run `aba release` as admin."
		}
		switch messageBox(title, text, mbYesNoCancel|mbIconError) {
		case idYes:
			if cli != "" {
				RunElevated(cli, "kill", a.ID)
			}
		case idNo:
			if cli != "" && oneClick {
				RunElevated(cli, "trust", a.ID)
			} else if cli != "" {
				RunElevated(cli, "resume", a.ID)
			}
		}
	case isolated:
		text := body + "\nYour " + platform.PC + " is isolated from the network (ABA's own alerts still get out).\n\nYes = Restore the internet now (only if you're sure)\nNo = Keep it isolated"
		if messageBox(title, text, mbYesNo|mbIconError) == idYes {
			if cli != "" {
				RunElevated(cli, "release")
			}
		}
	case a.Kind == alerts.KindDecoyRetired || a.Process == nil || a.Process.Image == "":
		messageBox(title, body, mbOK|mbIconInfo)
	default:
		// Nothing was done to it: one click to say it's yours.
		icon := uint32(mbIconWarning)
		ask := "\nShould " + a.ExeName() + " be reading " + baitWhat(a) + "?\n\n"
		if _, why := trust.Rule(a); why == "" {
			ask += "Yes = It's mine: trust it for this, no more alerts about it\n"
		} else {
			ask += "Yes = It's mine (just this once: " + why + ")\n"
		}
		ask += "No = Not sure: keep alerting (review later with `aba alerts`)" + warnings(a)
		if !a.Process.Signature.Valid || a.Tier == config.TierCritical {
			icon = mbIconError
		}
		if messageBox(title, body+ask, mbYesNo|icon) == idYes && cli != "" {
			RunElevated(cli, "trust", a.ID)
		}
	}
}

// browserPopup is the popup about a genuine browser that went through a fake
// profile (classify.Verdict Host): the text, the buttons, and the aba
// command each answer runs (nil: none). It's never "It's mine: trust it":
// one click would let every later stealer running its code inside the same
// browser through.
func browserPopup(a *alerts.Alert, body string) (text string, flags uint32, yes, no []string) {
	b := alerts.BrowserName(a.ExeName())
	frozen := a.Did(config.ActionFreeze) && !a.Did(config.ActionKill)
	isolated := a.Did(config.ActionIsolate) || a.Did(config.ActionDisableAdapters)
	isoNote := ""
	if isolated {
		isoNote = "\n\nYour " + platform.PC + " is isolated from the network too. When it's safe, run `aba release` as admin."
	}
	check := "Check " + b + "'s extensions and remove any you don't know. If you didn't add one lately, something on this " + platform.PC + " is running its code inside " + b + ": follow the steps in `aba alerts show " + a.ID + "`."
	switch {
	case frozen:
		text = body + "\nABA froze that " + b + ", all of it, and what started it: something ran its own code inside it.\n\n" +
			"Kill them?\n" +
			"Yes = Kill them (recommended)\n" +
			"No = Unfreeze them (this time only: nothing gets trusted)\n" +
			"Cancel = Decide later (they stay frozen)" + isoNote
		return text, mbYesNoCancel | mbIconError, []string{"kill", a.ID}, []string{"resume", a.ID}
	case a.Verdict.KeepRunning && a.Did(config.ActionBlockProgram):
		// (The alert's summary, at the top, already says it was left running
		// and every window of it cut off.)
		text = body + "\n" + check + "\n\n" +
			"Give " + b + " its internet back now?\n" +
			"Yes = Restore it now (nothing gets trusted)\n" +
			"No = Keep it cut (recommended until you've checked)" + isoNote
		return text, mbYesNo | mbIconError, []string{"resume", a.ID}, nil
	case a.Verdict.KeepRunning:
		text = body + "\n" + check + isoNote
		return text, mbOK | mbIconError, nil, nil
	}
	// Gone before ABA could look, or nothing was configured to stop it.
	what := "Your settings don't freeze programs, so that " + b + " (it isn't the one you're using) is still running."
	if a.Process != nil && a.Process.Exited {
		what = "Nothing of that " + b + " is left to stop now."
	}
	text = body + "\n" + what + " Something on this " + platform.PC + " starts " + b + " to run its own code inside it: follow the steps in `aba alerts show " + a.ID + "`." + isoNote
	return text, mbOK | mbIconError, nil, nil
}

// baitWhat names what the program read, for the popup question.
func baitWhat(a *alerts.Alert) string {
	if len(a.Verdict.Swept) > 1 {
		return fmt.Sprintf("the data of %d different apps", len(a.Verdict.Swept))
	}
	if len(a.Baits) > 0 && a.Baits[0].Name != "" {
		return a.Baits[0].Name
	}
	return "this file"
}

// warnings are the red flags worth repeating next to the question.
func warnings(a *alerts.Alert) string {
	var w string
	if a.Process != nil && !a.Process.Signature.Valid {
		w += "\n\nIt isn't signed by any publisher, which is how most stealers look. Only say it's yours if you built or installed it yourself."
	}
	if len(a.Verdict.Swept) > 1 {
		w += "\n\nIt went through several apps' data one after another. That's what stealers do; real apps only touch their own."
	}
	return w
}

func accessVerb(access string) string {
	switch access {
	case "delete":
		return "deleted"
	case "write":
		return "changed"
	case "swap":
		return "swapped the address on"
	case "mine":
		return "tried to mine at"
	}
	return "read"
}

func procBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// sentence starts s with a capital letter. Verdict reasons are written in
// lower case (they're also list items); the popup's first line is a sentence.
func sentence(s string) string {
	for i, r := range s {
		return strings.ToUpper(string(r)) + s[i+len(string(r)):]
	}
	return s
}
