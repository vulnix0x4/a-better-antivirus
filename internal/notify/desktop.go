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
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
)

// Envelope is what the service hands the popup process on its standard input
// (the alert files are for administrators only; the popup runs as you).
type Envelope struct {
	Alert         *alerts.Alert `json:"alert,omitempty"`
	LearningEnded bool          `json:"learningEnded,omitempty"`
	Trusted       int           `json:"trusted,omitempty"` // programs on the trust list
}

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
	fmt.Fprintln(&b, a.Summary)
	if p := a.Process; p != nil {
		fmt.Fprintf(&b, "\nProgram: %s (pid %d)\n", a.ExeName(), p.PID)
		if p.Image != "" {
			fmt.Fprintln(&b, p.Image)
		}
		fmt.Fprintf(&b, "%s: %s\n", vouchLabel, p.Signature)
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
	if access == "delete" {
		return "deleted"
	}
	return "read"
}

func procBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
