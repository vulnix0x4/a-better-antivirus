package autopsy

// Which of the three answers the autopsy gives, and in what words.
//
//   - It read real things: only on proof. The flight recorder saw one of its
//     processes open a real store's file (and can name the process for
//     certain), it has one open right now, or an archive it has open holds a
//     byte-for-byte copy of one.
//   - No sign it read anything real: only when every real store there is was
//     watched the whole time the program ran, every opener could be named,
//     nothing was dropped, and nothing points the other way. Even then it's
//     worded as what it is: ABA didn't see it, which isn't proof it didn't.
//   - ABA can't tell: everything else, with every reason.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/netrec"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

// facts are what the answer is decided from.
type facts struct {
	recorderOn  bool
	recorderWhy string // why it isn't on
	res         recorder.Result
	start       time.Time // when the first of its processes started; zero if unknown
	startWhy    string
	baitAt      time.Time
	held        []alerts.StoreRead // real stores' files it has open now
	stagedReal  []stagedFact       // byte-for-byte copies of real files among what it staged
	leads       []string           // other things that point to a theft without proving it
	// ownBusy are the stores of a genuine browser that had been running
	// normally and is caught (see Case.Running): it opens its own data all
	// the time, so whether the code in it took that data can't be told.
	ownBusy []baits.Store

	// The network record (see decide_net.go).
	netOn  bool
	netWhy string // why it isn't on
	net    netrec.Result
	// busy are processes of a genuine browser that had been running
	// normally (Case.Running): they send all the time.
	busy            map[uint32]bool
	frozen, blocked bool
	alertID         string
}

// busyLine is the "can't tell" for a store its own, normally running browser
// had open or opened.
func busyLine(s baits.Store) string {
	name := strings.TrimPrefix(s.Name, "your ")
	return "This is the genuine " + name + " and it had been running normally: it opens its own passwords and cookies all the time, so ABA can't tell which of those opens were for the code that opened the fake profile. Treat what's saved in that " + name + " as taken."
}

type stagedFact struct {
	path, store, name, kind, what string
	held                          bool
	at                            time.Time
}

// decide fills in the answer, the words and the lists of the autopsy.
func decide(f facts, a *alerts.Autopsy) {
	a.ProcessStart, a.BaitAt = f.start, f.baitAt

	// What it certainly read.
	var reads []alerts.StoreRead
	for _, r := range f.res.Reads {
		how := "the flight recorder saw it open it"
		if r.Via != "" {
			how = "the flight recorder saw a program it started open it (" + r.Via + ")"
		}
		reads = append(reads, alerts.StoreRead{Store: r.Store, Name: r.StoreName, Kind: r.Kind, Path: r.Path, At: r.First, Count: r.Count, PID: r.PID, Image: r.Image, How: how})
	}
	reads = append(reads, f.held...)
	var leads []string
	for _, s := range f.stagedReal {
		if s.held {
			reads = append(reads, alerts.StoreRead{Store: s.store, Name: s.name, Kind: s.kind, Path: s.path, At: s.at,
				How: "a copy of it, byte for byte, is in " + s.what + " it has open"})
		} else {
			leads = append(leads, fmt.Sprintf("A byte-for-byte copy of %s's file appeared in %s at %s, while it was running. ABA can't prove it made it, but nothing else normally copies that file there.",
				s.name, s.path, clock(s.at)))
		}
	}
	leads = append(leads, f.leads...)
	sort.SliceStable(reads, func(i, j int) bool { return reads[i].At.Before(reads[j].At) })
	a.Reads, a.Leads = reads, leads

	// How well each store was watched.
	present := 0
	var watched []string
	var notWatched []string
	for _, c := range f.res.Stores {
		w := alerts.StoreWatch{Store: c.Store, Name: c.Name, Kind: c.Kind, Watched: c.Watched, Absent: c.Absent, Since: c.Since, Why: c.Why}
		a.Watched = append(a.Watched, w)
		if c.Absent && !c.Watched {
			continue
		}
		if c.Watched && c.Files == 0 {
			continue // its folder is watched, and there's nothing in it yet
		}
		present++
		if c.Watched {
			if !hasName(watched, c.Name) { // two stores can share a name (the Credential Manager's two folders)
				watched = append(watched, c.Name)
			}
		} else {
			notWatched = append(notWatched, c.Name+": "+c.Why)
		}
	}

	// Why ABA might not be able to tell.
	var unsure []string
	for _, s := range f.ownBusy {
		unsure = append(unsure, busyLine(s))
	}
	if !f.recorderOn {
		why := f.recorderWhy
		if why == "" {
			why = "it's switched off"
		}
		unsure = append(unsure, "The flight recorder, which notes who opens your real passwords, cookies and keys, wasn't running: "+why+".")
	}
	if f.start.IsZero() {
		why := f.startWhy
		if why == "" {
			why = "it had exited"
		}
		unsure = append(unsure, "ABA doesn't know when the program started ("+why+"), so it can't tell how far back to look.")
	}
	if f.recorderOn {
		if !f.res.Forgot.IsZero() {
			unsure = append(unsure, "ABA's record of opens from before "+clock(f.res.Forgot)+" is gone (it keeps a day's worth), and the program was already running then.")
		}
		for _, l := range f.res.Lapses {
			unsure = append(unsure, fmt.Sprintf("Opens may have been missed around %s: %s.", clock(l.From), l.Why))
		}
		for _, d := range f.res.Doubts {
			unsure = append(unsure, fmt.Sprintf("%s was opened at %s by a program ABA can't pin on it for certain: %s.", capital(d.StoreName), clock(d.At), d.Why))
		}
		for _, n := range notWatched {
			unsure = append(unsure, capital(n)+".")
		}
	}
	a.Unsure = unsure

	byStore := groupReads(reads)
	net := netCheck(f, reads, len(unsure) == 0 && len(leads) == 0)
	switch {
	case len(reads) > 0:
		a.Answer = alerts.AnswerRead
		names := joinNames(storeNames(byStore))
		switch net.state {
		case alerts.SentNothing:
			a.Headline = "It opened " + names + ", but it was frozen before it sent anything: nothing left this " + pcWord + ". End it; you don't need to change anything."
		case alerts.SentSome:
			a.Headline = "It opened " + names + " and then connected to " + hosts(net.after) + ", so assume it was sent. Act on it now."
		default:
			a.Headline = "It opened " + names + ". Act on it now."
		}
		for _, g := range byStore {
			r := g[0]
			line := fmt.Sprintf("%s: %s at %s", capital(r.Name), fileList(g), clock(r.At))
			if rel := relBait(r.At, f.baitAt); rel != "" {
				line += ", " + rel
			}
			a.Summary = append(a.Summary, line+" ("+r.How+").")
			if net.state != alerts.SentNothing {
				a.Steps = append(a.Steps, advice(r.Store, r.Kind, r.Name)...)
			}
		}
		if len(unsure) > 0 {
			a.Summary = append(a.Summary, "It may have taken more than this: "+lower(unsure[0]))
		}
		if net.state != alerts.SentNothing {
			for _, s := range f.ownBusy {
				if _, read := idxStore(byStore, s.ID); !read {
					a.Steps = append(a.Steps, advice(s.ID, s.Kind, s.Name)...)
				}
			}
		}
		netWords(net, f, a)
	case len(unsure) > 0 || len(leads) > 0:
		a.Answer = alerts.AnswerUnknown
		first := ""
		if len(leads) > 0 {
			first = leads[0]
		} else {
			first = unsure[0]
		}
		switch net.state {
		case alerts.SentNothing:
			a.Headline = "ABA can't tell whether it read anything real, but nothing it ran sent anything over the network before it was frozen: nothing left this " + pcWord + ". You don't need to change anything."
			a.Summary = append(a.Summary, "Why ABA can't tell what it read: "+lower(first))
		case alerts.SentSome:
			a.Headline = "ABA can't tell whether it read anything real, and it connected to " + hosts(net.after) + " while it ran. " + first
		default:
			a.Headline = "ABA can't tell whether it read anything real. " + first
		}
		if len(watched) > 0 && f.recorderOn {
			a.Summary = append(a.Summary, "It saw no open of "+joinNames(watched)+" by it while it ran.")
		}
		if net.state != alerts.SentNothing {
			a.Summary = append(a.Summary, "To be safe, treat what ABA couldn't see as taken:")
			advised := map[string]bool{}
			for _, s := range f.ownBusy {
				advised[s.ID] = true
				a.Steps = append(a.Steps, advice(s.ID, s.Kind, s.Name)...)
			}
			for _, n := range unwatchedStores(f.res.Stores, f.res.Doubts, f.stagedReal, !f.recorderOn || f.start.IsZero() || len(f.res.Lapses) > 0 || !f.res.Forgot.IsZero()) {
				if !advised[n.Store] {
					a.Steps = append(a.Steps, advice(n.Store, n.Kind, n.Name)...)
				}
			}
		}
		netWords(net, f, a)
	case present == 0:
		a.Answer = alerts.AnswerNoSign
		a.Headline = "No sign it read anything real: ABA found none of the usual places your passwords, cookies, wallets and keys are kept on this " + pcWord + ", so there was nothing of that kind to take."
		a.Summary = append(a.Summary, "ABA only knows the places listed in its catalog; data kept anywhere else wasn't watched.")
		netNeutral(net, a)
	default:
		a.Answer = alerts.AnswerNoSign
		since := ""
		if s := earliestSince(f.res.Stores); !s.IsZero() {
			since = " (since " + day(s) + ")"
		}
		a.Headline = "No sign it read anything real. ABA was watching " + joinNames(watched) + since + " the whole time it ran, and saw it open none of them."
		a.Summary = append(a.Summary, "That's what ABA saw, not proof: "+limits)
		netNeutral(net, a)
	}
}

// groupReads groups reads by store, in the order of each store's first read.
func groupReads(reads []alerts.StoreRead) [][]alerts.StoreRead {
	idx := map[string]int{}
	var out [][]alerts.StoreRead
	for _, r := range reads {
		i, ok := idx[r.Store]
		if !ok {
			i = len(out)
			idx[r.Store] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], r)
	}
	return out
}

// idxStore finds the group of reads of store id.
func idxStore(groups [][]alerts.StoreRead, id string) (int, bool) {
	for i, g := range groups {
		if g[0].Store == id {
			return i, true
		}
	}
	return 0, false
}

func storeNames(groups [][]alerts.StoreRead) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g[0].Name)
	}
	return out
}

// fileList names the files of one store that were read.
func fileList(g []alerts.StoreRead) string {
	seen := map[string]bool{}
	var names []string
	for _, r := range g {
		n := baseName(r.Path)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// unwatchedStores are the stores ABA couldn't vouch for. all: none of them
// could be (no recorder, no start time…).
func unwatchedStores(cov []recorder.Coverage, doubts []recorder.Doubt, staged []stagedFact, all bool) []recorder.Coverage {
	doubted := map[string]bool{}
	for _, d := range doubts {
		doubted[d.Store] = true
	}
	for _, s := range staged {
		doubted[s.store] = true
	}
	var out []recorder.Coverage
	for _, c := range cov {
		if c.Absent && !c.Watched && !doubted[c.Store] {
			continue
		}
		if all || !c.Watched || doubted[c.Store] {
			out = append(out, c)
		}
	}
	return out
}

func earliestSince(cov []recorder.Coverage) time.Time {
	var t time.Time
	for _, c := range cov {
		if c.Watched && !c.Since.IsZero() && (t.IsZero() || c.Since.Before(t)) {
			t = c.Since
		}
	}
	return t
}

// relBait says when at was, relative to the first bait being opened.
func relBait(at, bait time.Time) string {
	if at.IsZero() || bait.IsZero() {
		return ""
	}
	d := bait.Sub(at)
	word := "before"
	if d < 0 {
		d, word = -d, "after"
	}
	return dur(d) + " " + word + " it opened the bait"
}

func dur(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1f s", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
	return fmt.Sprintf("%.1f h", d.Hours())
}

func clock(t time.Time) string { return t.Local().Format("15:04:05") }
func day(t time.Time) string {
	if time.Since(t) < 20*time.Hour {
		return t.Local().Format("15:04")
	}
	return t.Local().Format("Jan 2 15:04")
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return "nothing"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	if len(names) > 6 {
		return fmt.Sprintf("%s and %d more places your secrets are kept", strings.Join(names[:5], ", "), len(names)-5)
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func lower(s string) string {
	if s == "" || (len(s) > 1 && s[1] >= 'A' && s[1] <= 'Z') {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// advice is what to do about a store that was (or may have been) read.
func advice(id, kind, name string) []string {
	n := capital(name)
	switch id {
	case "telegram":
		return []string{n + ": on your phone, open Telegram > Settings > Devices and terminate all other sessions."}
	case "discord":
		return []string{n + ": change your Discord password (that ends the stolen login) and check for messages sent in your name."}
	case "ssh":
		return []string{n + ": remove them from every server and from GitHub, GitLab and the like, and make new ones."}
	case "aws", "aws-keys":
		return []string{n + ": deactivate them in the AWS console and make new ones."}
	case "git-credentials":
		return []string{n + ": revoke the tokens saved in it (GitHub > Settings > Developer settings, and the like)."}
	case "keychain":
		return []string{n + ": change your Mac login password, then the passwords saved in the keychain, email first."}
	case "keyring":
		return []string{n + ": change your login password, then the passwords saved in it, email first."}
	case "credman", "credman-local":
		return []string{n + ": change the passwords saved in it (Control Panel > Credential Manager)."}
	case "filezilla":
		return []string{n + ": change the passwords of the servers saved in it."}
	}
	switch kind {
	case baits.StoreBrowser:
		return []string{n + ": from another device, sign out of every site you're logged in to in it (\"sign out of all devices\"), then change the passwords saved in it, email first. Stolen cookies stay valid until you sign out."}
	case baits.StoreWallet:
		return []string{n + ": move the funds to a new wallet made on a clean device, now. Treat its recovery phrase as known to the thief."}
	case baits.StoreSession:
		return []string{n + ": sign out of all devices in it and change its password."}
	}
	return []string{n + ": change the passwords saved in it."}
}

func hasName(list []string, n string) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}
