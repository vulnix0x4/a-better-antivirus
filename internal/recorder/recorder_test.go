package recorder

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
)

var t0 = time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC)

func stores() []baits.Store {
	return []baits.Store{
		{ID: "chrome", Name: "your Chrome", Kind: baits.StoreBrowser, Root: "/u/chrome", Files: []string{"Local State", "*/Login Data", "*/Cookies"}, Skip: []string{"Profile 23"}},
		{ID: "exodus", Name: "your Exodus wallet", Kind: baits.StoreWallet, Root: "/u/exodus", Files: []string{"exodus.wallet/seed.seco"}},
	}
}

func newRec(t *testing.T) *Recorder {
	r := New()
	r.now = func() time.Time { return t0.Add(time.Hour) }
	r.SetStores(stores(), func(p string) bool { return strings.Contains(p, "Profile 23") })
	r.Watching("chrome", 3, t0.Add(-time.Hour))
	r.Watching("exodus", 1, t0.Add(-time.Hour))
	return r
}

func p(s string) string { return filepath.FromSlash(s) }

func TestCertainReadByMember(t *testing.T) {
	r := newRec(t)
	start := t0
	r.Note(Open{At: t0.Add(2 * time.Second), Path: p("/u/chrome/Default/Login Data"), PID: 900, Start: start, Image: "/tmp/stealer"})
	r.Note(Open{At: t0.Add(3 * time.Second), Path: p("/u/chrome/Default/Login Data"), PID: 900, Start: start})
	// The browser itself: not a member.
	r.Note(Open{At: t0.Add(4 * time.Second), Path: p("/u/chrome/Default/Cookies"), PID: 50, Start: t0.Add(-time.Hour)})
	res := r.Query(Query{Members: []Member{{PID: 900, Start: start}}, From: start, To: t0.Add(time.Minute)})
	if len(res.Reads) != 1 {
		t.Fatalf("reads = %+v", res.Reads)
	}
	got := res.Reads[0]
	if got.Store != "chrome" || got.Count != 2 || !got.First.Equal(t0.Add(2*time.Second)) || got.Image != "/tmp/stealer" {
		t.Errorf("read = %+v", got)
	}
	if len(res.Doubts) != 0 {
		t.Errorf("doubts = %+v", res.Doubts)
	}
	for _, c := range res.Stores {
		if !c.Watched {
			t.Errorf("%s not watched: %s", c.Store, c.Why)
		}
	}
}

func TestBaitPathsAreNeverRecorded(t *testing.T) {
	r := newRec(t)
	if _, ok := r.Match(p("/u/chrome/Profile 23/Login Data")); ok {
		t.Fatal("the bait profile matched a real store")
	}
	r.Note(Open{At: t0, Path: p("/u/chrome/Profile 23/Login Data"), PID: 900, Start: t0})
	if n := r.Status().Entries; n != 0 {
		t.Errorf("%d entries", n)
	}
}

func TestReusedPIDIsNotTheSameProgram(t *testing.T) {
	r := newRec(t)
	// An earlier program with PID 900 opened the wallet, then exited.
	r.Note(Open{At: t0.Add(-10 * time.Minute), Path: p("/u/exodus/exodus.wallet/seed.seco"), PID: 900, Start: t0.Add(-20 * time.Minute)})
	res := r.Query(Query{Members: []Member{{PID: 900, Start: t0}}, From: t0.Add(-30 * time.Minute), To: t0.Add(time.Minute)})
	if len(res.Reads) != 0 || len(res.Doubts) != 0 {
		t.Errorf("reads %+v doubts %+v", res.Reads, res.Doubts)
	}
}

func TestNoStartTimeGoesByWhenItStarted(t *testing.T) {
	r := newRec(t)
	// Windows' Security log has no start time: the open is after the
	// member started, and it has run since, so it's its.
	r.Note(Open{At: t0.Add(5 * time.Second), Path: p("/u/exodus/exodus.wallet/seed.seco"), PID: 900})
	// Before it started: someone else's.
	r.Note(Open{At: t0.Add(-5 * time.Minute), Path: p("/u/chrome/Local State"), PID: 900})
	// A hair after it started: can't tell.
	r.Note(Open{At: t0.Add(10 * time.Millisecond), Path: p("/u/chrome/Default/Cookies"), PID: 900})
	res := r.Query(Query{Members: []Member{{PID: 900, Start: t0}}, From: t0.Add(-10 * time.Minute), To: t0.Add(time.Minute)})
	if len(res.Reads) != 1 || res.Reads[0].Store != "exodus" {
		t.Errorf("reads = %+v", res.Reads)
	}
	if len(res.Doubts) != 1 || res.Doubts[0].Path != p("/u/chrome/Default/Cookies") {
		t.Errorf("doubts = %+v", res.Doubts)
	}
}

func TestExitedHelperCountsThroughItsParent(t *testing.T) {
	r := newRec(t)
	// A child of the stealer opened the cookies and exited before the catch.
	r.Note(Open{At: t0.Add(2 * time.Second), Path: p("/u/chrome/Default/Cookies"), PID: 901, PPID: 900, Start: t0.Add(time.Second)})
	res := r.Query(Query{Members: []Member{{PID: 900, Start: t0}}, From: t0, To: t0.Add(time.Minute)})
	if len(res.Reads) != 1 || res.Reads[0].Via != "started by pid 900" {
		t.Errorf("reads = %+v", res.Reads)
	}
}

func TestUnknownOpenerIsADoubt(t *testing.T) {
	r := newRec(t)
	r.Note(Open{At: t0.Add(2 * time.Second), Path: p("/u/chrome/Default/Login Data")})
	res := r.Query(Query{Members: []Member{{PID: 900, Start: t0}}, From: t0, To: t0.Add(time.Minute)})
	if len(res.Reads) != 0 || len(res.Doubts) != 1 {
		t.Errorf("reads %+v doubts %+v", res.Reads, res.Doubts)
	}
}

func TestExitedMemberIsADoubt(t *testing.T) {
	r := newRec(t)
	r.Note(Open{At: t0.Add(2 * time.Second), Path: p("/u/chrome/Default/Login Data"), PID: 900})
	res := r.Query(Query{Members: []Member{{PID: 900}}, From: t0, To: t0.Add(time.Minute)})
	if len(res.Reads) != 0 || len(res.Doubts) != 1 {
		t.Errorf("reads %+v doubts %+v", res.Reads, res.Doubts)
	}
}

func TestCoverageOverTheWindow(t *testing.T) {
	r := New()
	r.now = func() time.Time { return t0.Add(time.Hour) }
	r.SetStores(stores(), nil)
	r.Watching("chrome", 3, t0.Add(10*time.Second)) // started watching after the program started
	r.Absent("exodus", t0.Add(-time.Hour))
	res := r.Query(Query{Members: []Member{{PID: 1, Start: t0}}, From: t0, To: t0.Add(time.Minute)})
	for _, c := range res.Stores {
		switch c.Store {
		case "chrome":
			if c.Watched || !strings.Contains(c.Why, "only started watching") {
				t.Errorf("chrome = %+v", c)
			}
		case "exodus":
			if !c.Absent || c.Watched {
				t.Errorf("exodus = %+v", c)
			}
		}
	}

	// A watch that lapsed in the middle.
	r.Watching("exodus", 1, t0.Add(-time.Hour))
	r.NotWatching("exodus", t0.Add(20*time.Second), "its watch was found gone")
	r.Watching("exodus", 1, t0.Add(30*time.Second))
	res = r.Query(Query{Members: []Member{{PID: 1, Start: t0}}, From: t0, To: t0.Add(time.Minute)})
	for _, c := range res.Stores {
		if c.Store == "exodus" && c.Watched {
			t.Errorf("exodus watched through a gap: %+v", c)
		}
	}
}

func TestLapses(t *testing.T) {
	r := newRec(t)
	r.Lost(t0.Add(time.Second), t0.Add(time.Second), "the kernel dropped events")
	r.Lost(t0.Add(time.Second+100*time.Millisecond), t0.Add(2*time.Second), "the kernel dropped events")
	r.Lost(t0.Add(-2*time.Hour), t0.Add(-2*time.Hour), "old")
	res := r.Query(Query{Members: []Member{{PID: 1, Start: t0}}, From: t0, To: t0.Add(time.Minute)})
	if len(res.Lapses) != 1 || !res.Lapses[0].To.Equal(t0.Add(2*time.Second)) {
		t.Errorf("lapses = %+v", res.Lapses)
	}
}

func TestBoundedAndForgetful(t *testing.T) {
	r := newRec(t)
	for i := 0; i < maxEntries+10; i++ {
		r.Note(Open{At: t0.Add(time.Duration(i) * time.Millisecond), Path: p("/u/chrome/Default/Cookies"), PID: uint32(i + 1), Start: t0})
	}
	if n := r.Status().Entries; n > maxEntries {
		t.Errorf("%d entries kept", n)
	}
	res := r.Query(Query{Members: []Member{{PID: 1, Start: t0}}, From: t0, To: t0.Add(time.Hour)})
	if res.Forgot.IsZero() {
		t.Error("dropping entries wasn't remembered")
	}
}

func TestSamePIDWithoutStartIsSplitOverTime(t *testing.T) {
	r := newRec(t)
	r.Note(Open{At: t0.Add(-time.Hour), Path: p("/u/chrome/Local State"), PID: 900})
	r.Note(Open{At: t0.Add(5 * time.Second), Path: p("/u/chrome/Local State"), PID: 900})
	res := r.Query(Query{Members: []Member{{PID: 900, Start: t0}}, From: t0, To: t0.Add(time.Minute)})
	if len(res.Reads) != 1 || !res.Reads[0].First.Equal(t0.Add(5*time.Second)) || res.Reads[0].Count != 1 {
		t.Errorf("reads = %+v", res.Reads)
	}
}
