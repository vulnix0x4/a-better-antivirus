package autopsy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

// A genuine Brave, running normally (started from cmd.exe), had something
// put into it that opened the fake profile. Brave had opened its own
// profile at startup, 9 s before the bait, and rewrote its Local State
// meanwhile. That's not "It opened your Brave": ABA can't tell.
type braveWorld struct {
	brave, chrome   baits.Store
	login, local    string
	chromeLogin     string
	bait, exe       string
	start           time.Time
	readOtherStores bool
}

func newBraveWorld(t *testing.T) *braveWorld {
	root := t.TempDir()
	w := &braveWorld{start: time.Now().Add(-20 * time.Second)}
	ud := filepath.Join(root, "Brave", "User Data")
	w.login = filepath.Join(ud, "Default", "Login Data")
	w.local = filepath.Join(ud, "Local State")
	w.bait = filepath.Join(ud, "Profile 13", "Login Data")
	cud := filepath.Join(root, "Chrome", "User Data")
	w.chromeLogin = filepath.Join(cud, "Default", "Login Data")
	w.exe = filepath.Join(root, "Brave", "Application", "brave.exe")
	write(t, w.login, []byte("the person's real Brave passwords"))
	write(t, w.bait, []byte("SQLite format 3\x00 fake"))
	write(t, w.chromeLogin, []byte("the person's real Chrome passwords"))
	write(t, w.exe, []byte("MZ brave"))
	write(t, w.local, []byte(`{"os_crypt":{"encrypted_key":"..."}}`)) // rewritten while it ran
	old := time.Now().Add(-time.Hour)
	for _, p := range []string{w.login, w.bait, w.chromeLogin, w.exe} {
		os.Chtimes(p, old, old)
	}
	w.brave = baits.Store{ID: "brave-profile", Name: "your Brave", Kind: baits.StoreBrowser, Root: ud, Files: []string{"Local State", "*/Login Data"}, Skip: []string{"Profile 13"}}
	w.chrome = baits.Store{ID: "chrome-profile", Name: "your Chrome", Kind: baits.StoreBrowser, Root: cud, Files: []string{"Local State", "*/Login Data"}}
	return w
}

func (w *braveWorld) run(t *testing.T, running map[uint32]string) *alerts.Autopsy {
	c := Case{AlertID: "20261124-140000-beef", PID: 900, Image: w.exe, Tree: []uint32{900, 901}, Frozen: []uint32{900, 901, 880},
		BaitAt: time.Now(), BaitFiles: map[string]string{w.bait: "extra profile inside your Brave"},
		Stores: []baits.Store{w.brave, w.chrome}, Running: running}
	h := Hooks{
		Recorder: func(q recorder.Query) (recorder.Result, string) {
			res := recorder.Result{Stores: []recorder.Coverage{
				{Store: w.brave.ID, Name: w.brave.Name, Kind: w.brave.Kind, Files: 2, Watched: true, Since: w.start.Add(-time.Hour)},
				{Store: w.chrome.ID, Name: w.chrome.Name, Kind: w.chrome.Kind, Files: 1, Watched: true, Since: w.start.Add(-time.Hour)}}}
			// Brave opening its own profile at startup, 9 s before the bait.
			res.Reads = append(res.Reads, recorder.Read{Store: w.brave.ID, StoreName: w.brave.Name, Kind: w.brave.Kind, Path: w.login,
				First: time.Now().Add(-9 * time.Second), Last: time.Now().Add(-9 * time.Second), Count: 1, PID: 900, Image: w.exe})
			if w.readOtherStores {
				res.Reads = append(res.Reads, recorder.Read{Store: w.chrome.ID, StoreName: w.chrome.Name, Kind: w.chrome.Kind, Path: w.chromeLogin,
					First: time.Now().Add(-time.Second), Last: time.Now().Add(-time.Second), Count: 1, PID: 900, Image: w.exe})
			}
			return res, ""
		},
		StartedAt:   func(pid uint32) (time.Time, error) { return w.start, nil },
		StagingDirs: func(*Case) []Dir { return []Dir{{Path: w.brave.Root, Depth: 1}} },
	}
	return Run(c, h)
}

func TestNormallyRunningBrowserCantBeToldApart(t *testing.T) {
	w := newBraveWorld(t)
	a := w.run(t, map[uint32]string{900: "brave-profile", 901: "brave-profile"})
	if a.Answer != alerts.AnswerUnknown {
		t.Fatalf("answer %s: %s\n%v", a.Answer, a.Headline, a.Summary)
	}
	if !strings.Contains(a.Headline+strings.Join(a.Unsure, " "), "This is the genuine Brave and it had been running normally") {
		t.Fatalf("headline %q, unsure %v", a.Headline, a.Unsure)
	}
	if len(a.Steps) == 0 {
		t.Fatal("no advice for what's saved in that Brave")
	}
	for _, l := range a.Leads {
		if strings.Contains(l, "byte-for-byte") {
			t.Fatalf("Brave rewriting its own Local State is no copy: %s", l)
		}
	}
	if len(a.Reads) != 0 {
		t.Fatalf("its own opens counted as read: %+v", a.Reads)
	}
}

// One created suspended never ran as a browser: what it opened, it opened
// for the stealer.
func TestSuspendedBrowserCopyStillCounts(t *testing.T) {
	w := newBraveWorld(t)
	if a := w.run(t, nil); a.Answer != alerts.AnswerRead || !strings.Contains(a.Headline, "your Brave") {
		t.Fatalf("answer %s: %s", a.Answer, a.Headline)
	}
}

// A normally running Brave that also opened Chrome's data: that's read.
func TestNormallyRunningBrowserReadingAnotherStore(t *testing.T) {
	w := newBraveWorld(t)
	w.readOtherStores = true
	a := w.run(t, map[uint32]string{900: "brave-profile"})
	if a.Answer != alerts.AnswerRead || !strings.Contains(a.Headline, "your Chrome") || strings.Contains(a.Headline, "your Brave") {
		t.Fatalf("answer %s: %s", a.Answer, a.Headline)
	}
	brave := false
	for _, s := range a.Steps {
		brave = brave || strings.Contains(s, "Brave")
	}
	if !brave || !strings.Contains(strings.Join(a.Unsure, " "), "genuine Brave") {
		t.Fatalf("its own Brave still to be treated as taken: steps %v, unsure %v", a.Steps, a.Unsure)
	}
}
