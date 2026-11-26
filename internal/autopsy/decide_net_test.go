package autopsy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/netrec"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

const stealerPID = 900

var (
	discord = netip.MustParseAddrPort("162.159.135.232:443")
	ipAPI   = netip.MustParseAddrPort("208.95.112.1:80")
	readAt  = start.Add(6 * time.Second) // when it opened the real Discord token
)

// netOf runs a network record that began an hour before the stealer started,
// with what setup adds, and asks it about the stealer.
func netOf(setup func(r *netrec.Record)) netrec.Result {
	r := netrec.New()
	r.Began(start.Add(-time.Hour), nil)
	r.Started(stealerPID, 1, start, "stealer.exe")
	if setup != nil {
		setup(r)
	}
	return r.Query(netrec.Query{Members: []netrec.Member{{PID: stealerPID, Start: start}}, From: start, To: baitAt.Add(2 * time.Second)})
}

func discordRead() recorder.Result {
	cov := append(watchedAll(), recorder.Coverage{Store: "discord", Name: "your Discord login", Kind: baits.StoreSession, Files: 1, Watched: true, Since: start.Add(-time.Hour)})
	return recorder.Result{Stores: cov,
		Reads: []recorder.Read{{Store: "discord", StoreName: "your Discord login", Kind: baits.StoreSession, Path: `C:\u\AppData\Roaming\discord\Local Storage\leveldb\000003.log`, First: readAt, PID: stealerPID, Count: 1}}}
}

func netFacts(res netrec.Result) facts {
	return facts{recorderOn: true, start: start, baitAt: baitAt, res: discordRead(), netOn: true, net: res, frozen: true, blocked: true, alertID: "a1"}
}

// Answer 1: it opened real data, and the record proves nothing left.
func TestNothingSent(t *testing.T) {
	a := run(netFacts(netOf(nil)))
	if a.Answer != alerts.AnswerRead || a.Sent != alerts.SentNothing {
		t.Fatalf("answer %s sent %s (%q, %q)", a.Answer, a.Sent, a.Headline, a.SentWhy)
	}
	if !strings.Contains(a.Headline, "your Discord login, but it was frozen before it sent anything: nothing left this") ||
		!strings.Contains(a.Headline, "you don't need to change anything") {
		t.Errorf("headline = %q", a.Headline)
	}
	if len(a.Steps) != 0 {
		t.Errorf("nothing left: no change-your-password steps, got %q", a.Steps)
	}
	all := strings.Join(a.Summary, " ")
	for _, want := range []string{"aba kill a1", "cut off from the network", "missed nothing"} {
		if !strings.Contains(all, want) {
			t.Errorf("summary lacks %q: %q", want, a.Summary)
		}
	}
	if Short(a) != a.Headline {
		t.Errorf("short = %q", Short(a))
	}
}

// Sends before it opened anything (a geolocation check) carry none of it:
// still answer 1, and they're mentioned plainly.
func TestSentOnlyBeforeReading(t *testing.T) {
	res := netOf(func(r *netrec.Record) {
		r.Resolved(start.Add(time.Second), stealerPID, "ip-api.com", []netip.Addr{ipAPI.Addr()})
		r.Send(start.Add(2*time.Second), stealerPID, ipAPI, 0, true, false)
		r.Send(start.Add(2*time.Second), stealerPID, ipAPI, 120, false, false)
	})
	a := run(netFacts(res))
	if a.Sent != alerts.SentNothing {
		t.Fatalf("sent = %s (%q)", a.Sent, a.SentWhy)
	}
	if !strings.Contains(strings.Join(a.Summary, " "), "Before it opened anything of yours, it sent about 120 bytes to ip-api.com (208.95.112.1:80)") {
		t.Errorf("summary = %q", a.Summary)
	}
	if len(a.Sends) != 1 || a.Sends[0].After {
		t.Errorf("sends = %+v", a.Sends)
	}
}

// Answer 2: a connection out after it opened real data, however small.
func TestSentAfterReading(t *testing.T) {
	res := netOf(func(r *netrec.Record) {
		r.Resolved(readAt, stealerPID, "discord.com", []netip.Addr{discord.Addr()})
		r.Send(readAt.Add(time.Second), stealerPID, discord, 0, true, false)
		r.Send(readAt.Add(time.Second), stealerPID, discord, 517, false, false)
		r.Send(readAt.Add(1200*time.Millisecond), stealerPID, discord, 2400, false, false)
	})
	a := run(netFacts(res))
	if a.Answer != alerts.AnswerRead || a.Sent != alerts.SentSome {
		t.Fatalf("answer %s sent %s", a.Answer, a.Sent)
	}
	if a.Headline != "It opened your Discord login and then connected to discord.com, so assume it was sent. Act on it now." {
		t.Errorf("headline = %q", a.Headline)
	}
	if len(a.Steps) == 0 || !strings.Contains(a.Steps[0], "change your Discord password") {
		t.Errorf("steps = %q", a.Steps)
	}
	if !strings.Contains(strings.Join(a.Summary, " "), "After it opened your data, it sent about 2 KB to discord.com (162.159.135.232:443)") {
		t.Errorf("summary = %q", a.Summary)
	}
	if !strings.Contains(Short(a), "First: ") {
		t.Errorf("short = %q", Short(a))
	}

	// A connection alone, nothing sent on it yet: still assume it was sent.
	a = run(netFacts(netOf(func(r *netrec.Record) { r.Send(readAt.Add(time.Second), stealerPID, discord, 0, true, false) })))
	if a.Sent != alerts.SentSome || !strings.Contains(a.Headline, "connected to 162.159.135.232") {
		t.Errorf("connect only: %s %q", a.Sent, a.Headline)
	}
}

// What it started counts as it; loopback (the miner trap's fake pool among
// it) never does; the local network does.
func TestChildrenLoopbackAndLAN(t *testing.T) {
	a := run(netFacts(netOf(func(r *netrec.Record) {
		r.Send(readAt.Add(time.Second), stealerPID, netip.MustParseAddrPort("127.0.0.1:8080"), 300, false, false)
		r.Send(readAt.Add(time.Second), stealerPID, netip.MustParseAddrPort("127.97.98.97:443"), 300, false, false)
		r.Send(readAt.Add(time.Second), stealerPID, netip.MustParseAddrPort("[::1]:443"), 300, false, false)
		r.Send(readAt.Add(time.Second), stealerPID, netip.MustParseAddrPort("224.0.0.251:5353"), 300, false, true)
	})))
	if a.Sent != alerts.SentNothing {
		t.Errorf("loopback and multicast must not count: %s %+v", a.Sent, a.Sends)
	}

	a = run(netFacts(netOf(func(r *netrec.Record) {
		r.Started(901, stealerPID, start.Add(3*time.Second), "curl.exe")
		r.Started(902, 901, start.Add(4*time.Second), "helper.exe")
		r.Send(readAt.Add(2*time.Second), 902, discord, 900, false, false)
	})))
	if a.Sent != alerts.SentSome || len(a.Sends) != 1 || a.Sends[0].PID != 902 || !strings.Contains(a.Sends[0].Via, "started by pid 901") {
		t.Fatalf("grandchild: %s %+v", a.Sent, a.Sends)
	}
	if !strings.Contains(strings.Join(a.Summary, " "), "a program it started (helper.exe) sent about 900 bytes") {
		t.Errorf("summary = %q", a.Summary)
	}

	a = run(netFacts(netOf(func(r *netrec.Record) {
		r.Send(readAt.Add(time.Second), stealerPID, netip.MustParseAddrPort("192.168.89.1:443"), 4000, false, false)
	})))
	if a.Sent != alerts.SentSome || !a.Sends[0].LAN || !strings.Contains(strings.Join(a.Summary, " "), "a device on your local network") {
		t.Errorf("LAN: %s %+v %q", a.Sent, a.Sends, a.Summary)
	}
}

// A process that had the number before it, or another program's child, isn't
// it.
func TestOtherProcessesDontCount(t *testing.T) {
	a := run(netFacts(netOf(func(r *netrec.Record) {
		// The program that had PID 900 before it, sending after it exited
		// (its exit is long before the stealer started).
		r.Started(stealerPID, 1, start.Add(-time.Hour), "old.exe")
		r.Exited(stealerPID, start.Add(-time.Hour), start.Add(-30*time.Minute))
		// Another program, and what it started.
		r.Started(500, 1, start.Add(-time.Minute), "browser.exe")
		r.Started(501, 500, start.Add(time.Second), "child.exe")
		r.Send(readAt.Add(time.Second), 500, discord, 900, false, false)
		r.Send(readAt.Add(time.Second), 501, discord, 900, false, false)
	})))
	if a.Sent != alerts.SentNothing || len(a.Sends) != 0 {
		t.Errorf("sent %s %+v", a.Sent, a.Sends)
	}
}

// Answer 3: anything that leaves a hole in the record.
func TestCannotTellWhetherSent(t *testing.T) {
	cases := map[string]func(f *facts){
		"off": func(f *facts) { f.netOn, f.netWhy = false, "it's switched off (`aba recorder on`)" },
		"began late": func(f *facts) {
			r := netrec.New()
			r.Began(readAt.Add(time.Second), nil)
			f.net = r.Query(netrec.Query{Members: []netrec.Member{{PID: stealerPID, Start: start}}, From: start, To: baitAt})
		},
		"lapse": func(f *facts) {
			f.net.Lapses = []netrec.Lapse{{From: readAt.Add(time.Second), To: readAt.Add(2 * time.Second), Why: "Windows dropped some of its reports"}}
		},
		"behind": func(f *facts) { f.net.Behind = true },
		"forgot": func(f *facts) { f.net.Forgot = readAt.Add(time.Second) },
		"start unknown": func(f *facts) {
			f.start, f.startWhy = time.Time{}, "it had exited by the time ABA looked"
		},
		"browser": func(f *facts) {
			f.busy = map[uint32]bool{stealerPID: true}
			r := netrec.New()
			r.Began(start.Add(-time.Hour), nil)
			r.Started(stealerPID, 1, start, "msedge.exe")
			r.Send(readAt.Add(time.Second), stealerPID, discord, 100, false, false)
			f.net = r.Query(netrec.Query{Members: []netrec.Member{{PID: stealerPID, Start: start}}, From: start, To: baitAt})
		},
	}
	for name, change := range cases {
		f := netFacts(netOf(nil))
		change(&f)
		a := run(f)
		if a.Sent != alerts.SentUnknown || len(a.SentWhy) == 0 {
			t.Errorf("%s: sent %s why %q", name, a.Sent, a.SentWhy)
			continue
		}
		if len(a.Steps) == 0 || !strings.Contains(a.Headline, "Act on it now") {
			t.Errorf("%s: can't tell must keep the cautious advice: %q / %q", name, a.Headline, a.Steps)
		}
		if !strings.Contains(strings.Join(a.Summary, " "), "can't tell whether anything left") {
			t.Errorf("%s: summary = %q", name, a.Summary)
		}
	}

	// The record beginning after it started, but before it opened anything,
	// is enough.
	f := netFacts(netOf(nil))
	r := netrec.New()
	r.Began(start.Add(3*time.Second), nil)
	f.net = r.Query(netrec.Query{Members: []netrec.Member{{PID: stealerPID, Start: start}}, From: start, To: baitAt})
	if a := run(f); a.Sent != alerts.SentNothing {
		t.Errorf("began before the read: %s %q", a.Sent, a.SentWhy)
	}

	// A lapse before it opened anything doesn't matter.
	f = netFacts(netOf(nil))
	f.net.Lapses = []netrec.Lapse{{From: start, To: start.Add(time.Second), Why: "x"}}
	if a := run(f); a.Sent != alerts.SentNothing {
		t.Errorf("an early lapse: %s %q", a.Sent, a.SentWhy)
	}
}

// When ABA can't be sure it saw every read (a store it wasn't watching), a
// send counts from the moment it started, not from its first known read.
func TestUnsureReadsCountFromStart(t *testing.T) {
	f := netFacts(netOf(func(r *netrec.Record) { r.Send(start.Add(2*time.Second), stealerPID, ipAPI, 120, false, false) }))
	f.res.Stores[1].Watched, f.res.Stores[1].Why = false, "not watched"
	a := run(f)
	if a.Answer != alerts.AnswerRead || a.Sent != alerts.SentSome {
		t.Errorf("answer %s sent %s", a.Answer, a.Sent)
	}
	if !strings.Contains(strings.Join(a.Summary, " "), "While it ran, it sent about 120 bytes to 208.95.112.1:80") {
		t.Errorf("summary = %q", a.Summary)
	}
}

// Can't tell what it read, but nothing left: nothing to change either.
func TestCannotTellReadButNothingSent(t *testing.T) {
	cov := watchedAll()
	cov[1].Watched, cov[1].Why = false, "not watched"
	a := run(facts{recorderOn: true, start: start, baitAt: baitAt, res: recorder.Result{Stores: cov}, netOn: true, net: netOf(nil), frozen: true, alertID: "a2"})
	if a.Answer != alerts.AnswerUnknown || a.Sent != alerts.SentNothing {
		t.Fatalf("answer %s sent %s %q", a.Answer, a.Sent, a.SentWhy)
	}
	if !strings.Contains(a.Headline, "nothing left this") || len(a.Steps) != 0 {
		t.Errorf("headline %q steps %q", a.Headline, a.Steps)
	}

	a = run(facts{recorderOn: true, start: start, baitAt: baitAt, res: recorder.Result{Stores: cov}, netOn: true,
		net: netOf(func(r *netrec.Record) { r.Send(start.Add(time.Second), stealerPID, discord, 10, false, false) })})
	if a.Sent != alerts.SentSome || !strings.Contains(a.Headline, "connected to 162.159.135.232 while it ran") || len(a.Steps) == 0 {
		t.Errorf("sent: %s %q %q", a.Sent, a.Headline, a.Steps)
	}
}

func TestReportSaysWhatItSent(t *testing.T) {
	a := run(netFacts(netOf(func(r *netrec.Record) {
		r.Resolved(readAt, stealerPID, "discord.com", []netip.Addr{discord.Addr()})
		r.Send(readAt.Add(time.Second), stealerPID, discord, 0, true, false)
		r.Send(readAt.Add(time.Second), stealerPID, discord, 2400, false, false)
	})))
	text := PlainText(&alerts.Alert{ID: "a1", Autopsy: a})
	if !strings.Contains(text, "What it sent over the network") || !strings.Contains(text, "discord.com (162.159.135.232:443)  about 2 KB, 1 connection  pid 900  - after it opened your data") {
		t.Errorf("report:\n%s", text)
	}
	a = run(netFacts(netOf(nil)))
	text = PlainText(&alerts.Alert{ID: "a1", Autopsy: a})
	if !strings.Contains(text, "Nothing left this") || strings.Contains(text, "Do this now") {
		t.Errorf("report:\n%s", text)
	}
}
