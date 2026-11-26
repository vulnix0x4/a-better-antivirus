package autopsy

// The report in words: the short form for a notification, the full form
// for `aba autopsy` and the full report page (package report), which both
// show exactly these sections.

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// Short is the autopsy's answer in a sentence or two, for a notification.
func Short(ap *alerts.Autopsy) string {
	if ap == nil {
		return ""
	}
	s := ap.Headline
	if ap.Answer == alerts.AnswerRead && len(ap.Steps) > 0 {
		s += " First: " + ap.Steps[0]
	}
	return s
}

// Tone is how the answer should look: "bad" (it read your data and may
// have sent it), "warn" (it read your data but nothing left, or ABA can't
// tell) or "good" (no sign it read anything of yours).
func Tone(ap *alerts.Autopsy) string {
	switch {
	case ap == nil:
		return ""
	case ap.Answer == alerts.AnswerRead && ap.Sent != alerts.SentNothing:
		return "bad"
	case ap.Answer == alerts.AnswerNoSign:
		return "good"
	}
	return "warn"
}

// What each section of the report is (Section.Key), for the page that lays
// them out.
const (
	SecAnswer    = "answer"    // the headline, then the lines that explain it
	SecSteps     = "steps"     // what to do now
	SecUnsure    = "unsure"    // why ABA can't be sure
	SecLeads     = "leads"     // things that point to a theft without proving it
	SecSent      = "sent"      // what left the PC
	SecReads     = "reads"     // the real data it opened
	SecWatched   = "watched"   // what ABA was watching
	SecOpen      = "open"      // files it has open
	SecStaged    = "staged"    // files that appeared while it ran
	SecLeft      = "left"      // what will start it again
	SecAddresses = "addresses" // where it was sending: its webhook, bot, addresses
	SecProgram   = "program"   // the program itself
	SecDid       = "did"       // what ABA did, and what's left to do
	SecEvidence  = "evidence"  // where the evidence is
	SecNotes     = "notes"     // what couldn't be looked at
)

// Render is the full report, as plain text lines (the CLI styles them).
func Render(a *alerts.Alert) []Section {
	ap := a.Autopsy
	if ap == nil {
		return nil
	}
	var out []Section
	add := func(key, title string, lines ...string) {
		if len(lines) > 0 {
			out = append(out, Section{Key: key, Title: title, Lines: lines})
		}
	}
	add(SecAnswer, "Answer", append([]string{ap.Headline}, ap.Summary...)...)
	if len(ap.Steps) > 0 {
		var steps []string
		for i, s := range ap.Steps {
			steps = append(steps, fmt.Sprintf("%d. %s", i+1, s))
		}
		title := "Do this now, from another device"
		if ap.Answer != alerts.AnswerRead {
			title = "To be safe"
		}
		add(SecSteps, title, steps...)
	}
	add(SecUnsure, "Why ABA can't be sure", ap.Unsure...)
	add(SecLeads, "Leads", ap.Leads...)
	add(SecSent, "What it sent over the network", sentLines(ap)...)

	var reads []string
	for _, r := range ap.Reads {
		l := fmt.Sprintf("%s  %s  %s", clock(r.At), r.Name, r.Path)
		if rel := relBait(r.At, ap.BaitAt); rel != "" {
			l += "  (" + rel + ")"
		}
		if r.PID != 0 {
			l += fmt.Sprintf("  pid %d", r.PID)
		}
		if r.Count > 1 {
			l += fmt.Sprintf(", %d times", r.Count)
		}
		reads = append(reads, l+"  - "+r.How)
	}
	add(SecReads, "Real data it opened", reads...)

	var watch []string
	seenWatch := map[string]bool{}
	for _, w := range ap.Watched {
		if k := w.Name + "|" + fmt.Sprint(w.Watched, w.Absent, w.Why); seenWatch[k] {
			continue // two stores with one name (the Credential Manager's two folders)
		} else {
			seenWatch[k] = true
		}
		switch {
		case w.Watched:
			l := "watched   " + w.Name
			if !w.Since.IsZero() {
				l += " (since " + day(w.Since) + ")"
			}
			watch = append(watch, l)
		case w.Absent:
			watch = append(watch, "not here  "+w.Name)
		default:
			watch = append(watch, "NOT SEEN  "+w.Name+": "+w.Why)
		}
	}
	if !ap.ProcessStart.IsZero() {
		watch = append([]string{"It started at " + clock(ap.ProcessStart) + "; it opened the bait at " + clock(ap.BaitAt) + "."}, watch...)
	}
	add(SecWatched, "What ABA was watching while it ran", watch...)

	var files []string
	for _, f := range ap.OpenFiles {
		l := fmt.Sprintf("pid %d  %s", f.PID, visible(f.Path))
		if f.What != "" {
			l += "  (" + f.What + ")"
		}
		files = append(files, l)
	}
	add(SecOpen, "Files it has open", files...)

	var staged []string
	hidden := false
	for _, s := range ap.Staged {
		p := visible(s.Path)
		hidden = hidden || p != s.Path
		l := fmt.Sprintf("%s  %s  %s", clock(s.Appeared), size(s.Size), p)
		if s.HeldOpen {
			l += "  (it has this open)"
		}
		if s.What != "" {
			l += "  " + s.What
		}
		staged = append(staged, l)
		// Every entry that's a bait, a copy of a real file or named like
		// one; of the rest, only the first few.
		plain, more := 0, s.More
		for _, e := range s.Entries {
			if e.What == "" {
				if plain >= maxPlainEntries {
					more++
					continue
				}
				plain++
			}
			el := "    " + visible(e.Name)
			if e.What != "" {
				el += "  - " + e.What
			}
			staged = append(staged, el)
		}
		if more > 0 {
			staged = append(staged, fmt.Sprintf("    … and %d more", more))
		}
	}
	for _, u := range ap.Unpacked {
		staged = append(staged, fmt.Sprintf("%s  %d files, %s: the program's own code, unpacked there while it ran (it runs code from this folder); not listed", visible(u.Dir), u.Files, size(u.Size)))
	}
	if hidden {
		staged = append(staged, "(‹U+…› marks characters that don't show on screen: a folder or file named so you can't see or type its name is a stealer's trick to hide what it collects.)")
	}
	if len(staged) > 0 {
		staged = append(staged, "(Files that appeared in these places while it ran. Unless it has one open, ABA can't prove it made it.)")
	} else if len(ap.StagedWhere) > 0 {
		staged = append(staged, "Nothing new in the places stealers usually put what they collect.")
	}
	add(SecStaged, "Files that appeared while it ran", staged...)
	add(SecLeft, "What it left behind", ap.Left...)

	var addrs []string
	unsure, after := 0, -1
	for _, ad := range ap.Addresses {
		l := fmt.Sprintf("%-16s %s  (seen in its %s)", kindWord(ad.Kind), ad.Value, ad.Where)
		if ad.Kind == KindURL && !Shareable(ad.Kind, ad.Value, ad.Where) {
			// Only in its memory: as likely the text of its own libraries or
			// your data it collected as where it sends. Only the first few.
			if unsure++; unsure > maxUnsureURLs {
				continue
			}
			l += ", may be from your own data it collected"
			after = len(addrs) + 1
		}
		addrs = append(addrs, l)
	}
	if unsure > maxUnsureURLs {
		where := ""
		if ap.Evidence != "" {
			where = " (all of them are in autopsy.json in the evidence folder)"
		}
		l := fmt.Sprintf("… and %d more web addresses found only in its memory: text of its own libraries, or your data it collected, more likely than where it sends%s.", unsure-maxUnsureURLs, where)
		addrs = append(addrs[:after], append([]string{l}, addrs[after:]...)...)
	}
	if ap.AttackerWallet != "" {
		note := ap.WalletNote
		if note == "" {
			note = "what it swapped in for yours"
		}
		addrs = append(addrs, "attacker wallet  "+ap.AttackerWallet+"  ("+note+")")
	}
	if ap.MemoryScanned > 0 {
		addrs = append(addrs, fmt.Sprintf("(%s of its memory looked through.)", size(ap.MemoryScanned)))
	}
	addrs = append(addrs, reportHints(ap)...)
	add(SecAddresses, "Where it was sending", addrs...)
	add(SecProgram, "The program", programLines(a)...)
	add(SecDid, "What ABA did", didLines(a)...)

	var ev []string
	if ap.Evidence != "" {
		ev = append(ev, "Saved to "+ap.Evidence+" (administrators only).")
		if ap.MemoryImage {
			ev = append(ev, "It includes a copy of the program's memory, which holds whatever it collected: maybe your own passwords and cookies. Keep it to yourself.")
		}
		ev = append(ev, "To share what's safe to share: aba export-ioc "+a.ID)
	}
	add(SecEvidence, "Evidence", ev...)
	add(SecNotes, "Notes", ap.Notes...)
	return out
}

// sentLines are what the network record saw it send, and how sure that is.
func sentLines(ap *alerts.Autopsy) []string {
	var out []string
	for _, s := range ap.Sends {
		l := clock(s.First) + "  " + hostOf(s)
		if s.Name != "" && s.To != "" {
			l += " (" + s.To + ")"
		}
		var what []string
		if s.Bytes > 0 {
			what = append(what, "about "+amount(s.Bytes))
		}
		switch {
		case s.Conns == 1:
			what = append(what, "1 connection")
		case s.Conns > 1:
			what = append(what, fmt.Sprintf("%d connections", s.Conns))
		}
		if len(what) > 0 {
			l += "  " + strings.Join(what, ", ")
		}
		l += fmt.Sprintf("  pid %d", s.PID)
		if s.Via != "" {
			l += " (" + s.Image + ", " + s.Via + ")"
		}
		if s.LAN {
			l += "  on your local network"
		}
		switch {
		case !s.After:
			l += "  - before it opened anything of yours"
		case ap.Answer == alerts.AnswerRead:
			l += "  - after it opened your data"
		}
		out = append(out, l)
	}
	switch ap.Sent {
	case alerts.SentNothing:
		out = append(out, "Nothing left this "+pcWord+" once it could have had your data: ABA's network record ran the whole time and saw no send by it or anything it started.")
	case alerts.SentUnknown:
		for _, w := range ap.SentWhy {
			out = append(out, "ABA can't tell: "+lower(w))
		}
	}
	return out
}

// How much of the long lists the report shows.
const (
	maxPlainEntries = 20 // archive entries that are none of yours, per archive
	maxUnsureURLs   = 8  // web addresses found only in its memory
)

// visible shows the characters of a name that don't show on screen (a
// zero-width space, a direction mark, a space at the start or end of a
// folder's name) as ‹U+200B›, so a folder named to be invisible can be seen
// and found.
func visible(p string) string {
	parts := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return p
	}
	changed := false
	var b strings.Builder
	start := 0
	for _, part := range parts {
		i := strings.Index(p[start:], part) + start
		b.WriteString(p[start:i])
		start = i + len(part)
		blank := strings.TrimSpace(part) != part
		var e strings.Builder
		for _, r := range part {
			if hiddenRune(r) {
				fmt.Fprintf(&e, "‹U+%04X›", r)
				blank = true
				continue
			}
			e.WriteRune(r)
		}
		if blank {
			changed = true
			b.WriteString("\"" + e.String() + "\"")
		} else {
			b.WriteString(part)
		}
	}
	b.WriteString(p[start:])
	if !changed {
		return p
	}
	return b.String()
}

// hiddenRune: a character that takes no room or looks like a plain space.
func hiddenRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) || (unicode.IsSpace(r) && r != ' ') || r == 0x2800 || r == 0x3164 || r == 0x115F || r == 0x1160 || r == 0xFFA0
}

// Section is one part of the report.
type Section struct {
	Key   string // one of the Sec* constants
	Title string
	Lines []string
}

// kindWord is what an address is, in words.
func kindWord(kind string) string {
	switch kind {
	case KindTelegram:
		return "Telegram bot"
	case KindDiscord:
		return "Discord webhook"
	case KindURL:
		return "web address"
	}
	return kind
}

// reportHints say who can shut down the stealer's own mailbox, when it
// sends to a Discord webhook or a Telegram bot: both take them down once
// they're reported.
func reportHints(ap *alerts.Autopsy) []string {
	var discord, telegram bool
	for _, ad := range ap.Addresses {
		discord = discord || ad.Kind == KindDiscord
		telegram = telegram || ad.Kind == KindTelegram
	}
	var out []string
	if discord {
		out = append(out, "The Discord webhook is the stealer's own mailbox, not yours. You can report it to Discord (Trust & Safety, at dis.gd/request): Discord deletes webhooks used for stealing, and then nothing more reaches the thief through it.")
	}
	if telegram {
		out = append(out, "The Telegram bot is the stealer's own, not yours. You can report it to Telegram (abuse@telegram.org, with the bot's token): Telegram shuts such bots down.")
	}
	return out
}

// programLines are the caught program's details.
func programLines(a *alerts.Alert) []string {
	p := a.Process
	if p == nil {
		return nil
	}
	out := []string{fmt.Sprintf("Name: %s (pid %d)", a.ExeName(), p.PID)}
	if p.Image != "" {
		out = append(out, "File: "+visible(p.Image))
	}
	out = append(out, vouchWord+": "+p.Signature.String())
	if p.SHA256 != "" {
		out = append(out, "Fingerprint (SHA-256): "+p.SHA256)
	}
	if l := p.Origin.Line(p.Image); l != "" {
		out = append(out, l)
	}
	if len(p.Parents) > 0 {
		par := p.Parents[0]
		if par.Exited || par.Image == "" {
			out = append(out, fmt.Sprintf("Started by: a program that has ended since (pid %d)", par.PID))
		} else {
			out = append(out, fmt.Sprintf("Started by: %s (pid %d)", baseName(par.Image), par.PID))
		}
	}
	if p.CommandLine != "" {
		out = append(out, "Command line: "+p.CommandLine)
	}
	if p.User != "" {
		out = append(out, "Ran as: "+p.User)
	}
	return out
}

// didLines are what ABA did about the program, and the commands left to
// answer it with.
func didLines(a *alerts.Alert) []string {
	var out []string
	if !a.Time.IsZero() {
		l := "Caught on " + a.Time.Local().Format("Mon Jan 2 2006 at 15:04:05")
		if a.Instant {
			l += ", the moment it opened the bait"
		}
		if a.LatencyMS > 0 {
			l += fmt.Sprintf(" (stopped %d ms after)", a.LatencyMS)
		}
		out = append(out, l+".")
	}
	for _, r := range a.Actions {
		if r.OK {
			out = append(out, "Done: "+config.Action(r.Action).Done(r.Detail))
		} else {
			out = append(out, "Couldn't "+config.Action(r.Action).Verb()+": "+r.Detail)
		}
	}
	if a.Status == "resolved" {
		l := "Answered"
		if a.Note != "" {
			l += ": " + a.Note
		}
		out = append(out, l+".")
	}
	if rows := alerts.NextSteps(a); len(rows) > 0 {
		out = append(out, "To answer it, "+adminWhere+":")
		for _, r := range rows {
			out = append(out, r[0]+"  "+r[1])
		}
	}
	return out
}

func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

// PlainText is the report as plain text.
func PlainText(a *alerts.Alert) string {
	var b strings.Builder
	for _, s := range Render(a) {
		b.WriteString(s.Title + "\n")
		for _, l := range s.Lines {
			b.WriteString("  " + l + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}
