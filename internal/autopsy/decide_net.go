package autopsy

// Did anything leave this PC before the freeze? From ABA's network record
// (package netrec), three answers:
//
//   - Nothing left: only when the record ran unbroken, lost nothing and
//     caught up, from the moment it first opened real data (or, when ABA
//     can't be sure that's when, from its start) to the autopsy, and saw no
//     send at all by it or anything it started in that time.
//   - It sent something: any connection out of this PC, or any data sent,
//     after that moment. Not judged by size: a stolen login is a few hundred
//     bytes, as small as a handshake. Loopback never counts (it stays on
//     this PC); a device on the local network does (a router or a proxy
//     passes things on).
//   - ABA can't tell: everything else, with every reason.
//
// Sends before it first opened anything real carry none of it: they're
// listed, plainly ("it contacted ip-api.com before reading anything").

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/netrec"
)

type netAnswer struct {
	state  string
	why    []string // why ABA can't tell
	after  []alerts.NetSend
	before []alerts.NetSend
	all    []alerts.NetSend
	from   time.Time
	read   bool // from is when it first opened real data
}

// netCheck answers from the network record. certain: the reads are all
// there is to know (nothing unsure, no leads), so the first of them is when
// it first had your data.
func netCheck(f facts, reads []alerts.StoreRead, certain bool) netAnswer {
	var n netAnswer
	first, byRecorder := time.Time{}, true
	for _, r := range reads {
		if !strings.HasPrefix(r.How, "the flight recorder") {
			byRecorder = false // held or copied: when it opened it isn't known
		}
		if first.IsZero() || r.At.Before(first) {
			first = r.At
		}
	}
	if len(reads) > 0 && byRecorder && certain && !first.IsZero() {
		n.from, n.read = first, true
	} else {
		n.from = f.start
	}

	busy := false
	conv := func(s netrec.Send, after bool) alerts.NetSend {
		ns := alerts.NetSend{PID: s.PID, Image: s.Image, Via: s.Via, Name: s.Name, LAN: s.LAN, UDP: s.UDP,
			First: s.First, Last: s.Last, Bytes: s.Bytes, Conns: s.Conns, After: after}
		if after {
			ns.BytesAfter = s.Bytes
		}
		if s.Remote.IsValid() {
			ns.To = s.Remote.String()
		}
		return ns
	}
	for _, s := range f.net.Sends {
		if n.from.IsZero() {
			ns := conv(s, true)
			n.all = append(n.all, ns)
			if f.busy[s.PID] {
				busy = true
			} else {
				n.after = append(n.after, ns)
			}
			continue
		}
		before, after, okB, okA := s.Split(n.from)
		if okB {
			ns := conv(before, false)
			n.all = append(n.all, ns)
			n.before = append(n.before, ns)
		}
		if okA {
			ns := conv(after, true)
			n.all = append(n.all, ns)
			if f.busy[s.PID] {
				busy = true
			} else {
				n.after = append(n.after, ns)
			}
		}
	}

	switch {
	case len(n.after) > 0:
		n.state = alerts.SentSome
		return n
	case !f.netOn:
		why := f.netWhy
		if why == "" {
			why = "it's switched off"
		}
		n.why = append(n.why, "ABA's network record, which notes what programs send, wasn't running: "+why+".")
	case n.from.IsZero():
		why := f.startWhy
		if why == "" {
			why = "it had exited"
		}
		n.why = append(n.why, "ABA doesn't know when it started ("+why+"), so it can't tell how far back to look.")
	}
	if !f.frozen {
		n.why = append(n.why, "It wasn't frozen, so it could still send things after ABA looked.")
	}
	if busy {
		n.why = append(n.why, "Part of it ran inside a program that had been running normally (your browser), which was sending as usual: ABA can't tell what it sent from what that program sent.")
	}
	if f.netOn && !n.from.IsZero() {
		since := "it started"
		if n.read {
			since = "it opened your data"
		}
		if b := f.net.Began; b.IsZero() || b.After(n.from) {
			n.why = append(n.why, "ABA's network record was only running from "+clock(b)+" on, after "+since+".")
		}
		said, more := 0, 0
		for _, l := range f.net.Lapses {
			switch {
			case l.To.Before(n.from):
			case said == 3:
				more++
			default:
				said++
				n.why = append(n.why, fmt.Sprintf("Sends may have been missed around %s: %s.", clock(l.To), l.Why))
			}
		}
		if more > 0 {
			n.why = append(n.why, fmt.Sprintf("… and %d more moments like that.", more))
		}
		if !f.net.Forgot.IsZero() && f.net.Forgot.After(n.from) {
			n.why = append(n.why, "ABA's network record of what happened before "+clock(f.net.Forgot)+" is gone (it keeps a few hours), and it was already running then.")
		}
		if f.net.Behind {
			n.why = append(n.why, "ABA couldn't make sure its network record had caught up with the last moments before the freeze.")
		}
	}
	if len(n.why) > 0 {
		n.state = alerts.SentUnknown
	} else {
		n.state = alerts.SentNothing
	}
	return n
}

// hosts names where sends went: "discord.com and ip-api.com".
func hosts(sends []alerts.NetSend) string {
	var names []string
	seen := map[string]bool{}
	for _, s := range sends {
		h := hostOf(s)
		if !seen[h] {
			seen[h] = true
			names = append(names, h)
		}
	}
	if len(names) > 3 {
		return fmt.Sprintf("%s, %s, %s and %d more", names[0], names[1], names[2], len(names)-3)
	}
	return joinNames(names)
}

func hostOf(s alerts.NetSend) string {
	switch {
	case s.Name != "":
		return s.Name
	case s.To == "":
		return "other addresses"
	}
	if i := strings.LastIndex(s.To, ":"); i > 0 {
		return strings.Trim(s.To[:i], "[]")
	}
	return s.To
}

// sendLine says what one send was: "it sent about 3 KB to discord.com
// (162.159.135.232:443) at 14:00:07".
func sendLine(s alerts.NetSend, after bool) string {
	who := "it"
	if s.Via != "" {
		img := s.Image
		if img == "" {
			img = fmt.Sprintf("pid %d", s.PID)
		}
		who = "a program it started (" + img + ")"
	}
	where := hostOf(s)
	if s.Name != "" && s.To != "" {
		where += " (" + s.To + ")"
	} else if s.To != "" {
		where = s.To
	}
	if s.LAN {
		where += " on your local network"
	}
	bytes, at := s.Bytes, s.First
	if after {
		bytes = s.BytesAfter
	}
	l := who + " connected to " + where
	if bytes > 0 {
		l = fmt.Sprintf("%s sent about %s to %s", who, amount(bytes), where)
	}
	return l + " at " + clock(at)
}

// netWords adds what the network record says to a, for the answer given.
func netWords(n netAnswer, f facts, a *alerts.Autopsy) {
	a.Sent, a.SentWhy, a.Sends = n.state, n.why, n.all
	sort.SliceStable(a.Sends, func(i, j int) bool { return a.Sends[i].First.Before(a.Sends[j].First) })
	if len(n.before) > 0 && n.read {
		var ls []string
		for _, s := range n.before {
			ls = append(ls, sendLine(s, false))
		}
		a.Summary = append(a.Summary, "Before it opened anything of yours, "+strings.Join(ls, "; ")+". That was before it had your data.")
	}
	switch n.state {
	case alerts.SentSome:
		var ls []string
		for i, s := range n.after {
			if i == 4 {
				ls = append(ls, fmt.Sprintf("and %d more", len(n.after)-i))
				break
			}
			ls = append(ls, sendLine(s, true))
		}
		when := "After it opened your data, "
		if !n.read {
			when = "While it ran, "
		}
		a.Summary = append(a.Summary, when+strings.Join(ls, "; ")+".")
		for _, s := range n.after {
			if s.LAN {
				a.Summary = append(a.Summary, "An address on your local network still counts: it left this "+pcWord+", and a router or a proxy there passes things on to the internet.")
				break
			}
		}
	case alerts.SentNothing:
		since := "it started"
		if n.read {
			since = "it opened your data"
		}
		a.Summary = append(a.Summary, "From the moment "+since+" until it was frozen, neither it nor anything it started sent anything over the network: ABA's network record was running the whole time and missed nothing.")
		a.Summary = append(a.Summary, frozenLine(f))
		a.Summary = append(a.Summary, "(ABA sees what this program and the programs it started send; not data it may have handed to another program.)")
	case alerts.SentUnknown:
		if len(n.why) > 0 {
			a.Summary = append(a.Summary, "ABA can't tell whether anything left this "+pcWord+": "+lower(n.why[0]))
		}
	}
}

// netNeutral says where it connected, for a program that read nothing real:
// as information, not as a theft.
func netNeutral(n netAnswer, a *alerts.Autopsy) {
	a.Sent, a.SentWhy, a.Sends = n.state, n.why, n.all
	if len(n.all) > 0 {
		var ls []string
		for i, s := range n.all {
			if i == 4 {
				ls = append(ls, fmt.Sprintf("and %d more", len(n.all)-i))
				break
			}
			ls = append(ls, sendLine(s, false))
		}
		a.Summary = append(a.Summary, "While it ran, "+strings.Join(ls, "; ")+".")
	}
}

// amount is a number of bytes in words.
func amount(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d bytes", n)
	}
	return size(n)
}

func frozenLine(f facts) string {
	end := "End it (aba kill " + f.alertID + ") and delete anything it left behind; there's nothing else to do."
	switch {
	case f.frozen && f.blocked:
		return "It's frozen and cut off from the network now, so nothing more can leave. " + end
	case f.frozen:
		return "It's frozen now, so it can't send anything more. " + end
	}
	return end
}
