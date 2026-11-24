package autopsy

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

type world struct {
	home, chrome, real, bait, stage, zip, exe, evidence string
	store                                               baits.Store
	start                                               time.Time
}

func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newWorld(t *testing.T, stealReal bool) world {
	root := t.TempDir()
	w := world{home: filepath.Join(root, "home"), stage: filepath.Join(root, "tmp"), evidence: filepath.Join(root, "evidence")}
	w.chrome = filepath.Join(w.home, "Chrome")
	w.real = filepath.Join(w.chrome, "Default", "Login Data")
	w.bait = filepath.Join(w.chrome, "Profile 23", "Login Data")
	w.exe = filepath.Join(w.home, "Downloads", "game.bin")
	write(t, w.real, []byte("the person's real saved passwords, encrypted"))
	write(t, w.bait, []byte("SQLite format 3\x00 fake passwords"))
	write(t, w.exe, []byte("MZ...https://api.telegram.org/bot"+tok+"/sendDocument ... http://panel.example.org/gate.php"))
	w.store = baits.Store{ID: "chrome-profile", Name: "your Chrome", Kind: baits.StoreBrowser, Root: w.chrome, Files: []string{"*/Login Data"}, Skip: []string{"Profile 23"}}
	w.start = time.Now().Add(-2 * time.Second)

	// What the stealer staged: an archive of what it collected.
	w.zip = filepath.Join(w.stage, "x9f3", "out.zip")
	if err := os.MkdirAll(filepath.Dir(w.zip), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(w.zip)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	add := func(name, src string) {
		b, _ := os.ReadFile(src)
		e, _ := zw.Create(name)
		e.Write(b)
	}
	add("Browsers/Chrome/Profile 23/Login Data", w.bait)
	if stealReal {
		add("Browsers/Chrome/Default/Login Data", w.real)
	}
	e, _ := zw.Create("System.txt")
	e.Write([]byte("os: test"))
	zw.Close()
	f.Close()
	return w
}

func (w world) run(t *testing.T, held bool) *alerts.Autopsy {
	c := Case{AlertID: "20261123-140000-abcd", PID: 900, Image: w.exe, Tree: []uint32{900, 901}, Frozen: []uint32{900, 901},
		BaitAt: time.Now(), User: config.UserInfo{Profile: w.home}, BaitFiles: map[string]string{w.bait: "extra profile inside your Chrome"},
		Stores: []baits.Store{w.store}, Conns: []procinfo.Conn{{PID: 900, Proto: "tcp", Local: "10.0.0.2:5555", Remote: "185.199.1.7:443", State: "ESTABLISHED"}}}
	h := Hooks{
		Recorder: func(q recorder.Query) (recorder.Result, string) {
			if len(q.Members) != 2 || !q.From.Equal(w.start) {
				t.Errorf("query = %+v", q)
			}
			return recorder.Result{Stores: []recorder.Coverage{{Store: w.store.ID, Name: w.store.Name, Kind: w.store.Kind, Files: 1, Watched: true, Since: w.start.Add(-time.Hour)}}}, ""
		},
		StartedAt: func(pid uint32) (time.Time, error) {
			return w.start.Add(time.Duration(pid-900) * time.Millisecond), nil
		},
		OpenFiles: func(pid uint32) ([]string, error) {
			if pid == 900 && held {
				return []string{w.zip, "/usr/lib/libc.dylib"}, nil
			}
			return nil, nil
		},
		ReadMemory: func(pid uint32, limit int64, fn func(uint64, []byte) bool) (int64, error) {
			b := []byte("heap: https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEF0123456789 and https://mail.example.com/inbox")
			fn(0x1000, b)
			return int64(len(b)), nil
		},
		StagingDirs: func(*Case) []Dir { return []Dir{{Path: w.stage, Depth: 3}} },
		EvidenceDir: w.evidence,
		MemoryImage: true,
	}
	return Run(c, h)
}

func TestRunFindsAStagedCopyOfTheRealFile(t *testing.T) {
	w := newWorld(t, true)
	a := w.run(t, true)
	if a.Answer != alerts.AnswerRead {
		t.Fatalf("answer = %s: %s\n%v", a.Answer, a.Headline, a.Unsure)
	}
	if len(a.Staged) != 1 || !a.Staged[0].HeldOpen || a.Staged[0].Archive != "zip" {
		t.Fatalf("staged = %+v", a.Staged)
	}
	var sawBait, sawReal bool
	for _, e := range a.Staged[0].Entries {
		sawBait = sawBait || (strings.Contains(e.Name, "Profile 23") && strings.HasPrefix(e.What, "a bait"))
		sawReal = sawReal || (strings.Contains(e.Name, "Default") && strings.Contains(e.What, "same bytes as your real file"))
	}
	if !sawBait || !sawReal {
		t.Errorf("entries = %+v", a.Staged[0].Entries)
	}
	if len(a.OpenFiles) != 1 {
		t.Errorf("open files = %+v (system files should be left out)", a.OpenFiles)
	}

	kinds := map[string]string{}
	for _, ad := range a.Addresses {
		kinds[ad.Value] = ad.Kind + "/" + ad.Where
	}
	if kinds[tok] != KindTelegram+"/file" || kinds["185.199.1.7:443"] != KindConn+"/connection" ||
		!strings.HasPrefix(kinds["https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEF0123456789"], KindDiscord) {
		t.Errorf("addresses = %v", kinds)
	}

	// The evidence folder.
	for _, p := range []string{"README.txt", "autopsy.json", "program/game.bin.sample", "memory/pid-900.bin", "memory/pid-900.regions.txt"} {
		if _, err := os.Stat(filepath.Join(a.Evidence, p)); err != nil {
			t.Errorf("evidence: %v", err)
		}
	}
	if !a.MemoryImage || a.Staged[0].Saved == "" {
		t.Errorf("memory image %v, staged copy %q", a.MemoryImage, a.Staged[0].Saved)
	}
	var saved alerts.Autopsy
	b, _ := os.ReadFile(filepath.Join(a.Evidence, "autopsy.json"))
	if json.Unmarshal(b, &saved) != nil || saved.Answer != alerts.AnswerRead || saved.Finished.IsZero() {
		t.Errorf("autopsy.json: %s", b)
	}
	if fi, _ := os.Stat(a.Evidence); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("evidence folder is %v", fi.Mode().Perm())
	}

	// The shareable export: the token, the webhook, the connection and the
	// address in its file; not the mail address from its memory.
	ioc := MakeIOC(&alerts.Alert{ID: "x", Time: time.Now(), Process: &alerts.Process{Image: w.exe, SHA256: "ab"}, Autopsy: a}, w.home)
	var vals []string
	for _, s := range ioc.Sending {
		vals = append(vals, s.Value)
	}
	all := strings.Join(vals, " ")
	if !strings.Contains(all, tok) || !strings.Contains(all, "panel.example.org") || !strings.Contains(all, "185.199.1.7:443") || strings.Contains(all, "mail.example.com") {
		t.Errorf("export = %v", vals)
	}
	if !strings.HasPrefix(ioc.File.Path, "~") {
		t.Errorf("home folder not hidden: %s", ioc.File.Path)
	}
	out, _ := MarshalIOC(ioc)
	if strings.Contains(string(out), w.home) || strings.Contains(string(out), "memory") && strings.Contains(string(out), "pid-900") {
		t.Errorf("export leaks: %s", out)
	}
	if txt := PlainText(&alerts.Alert{ID: "x", Autopsy: a}); !strings.Contains(txt, "Real data it opened") {
		t.Errorf("report:\n%s", txt)
	}
}

func TestRunNoSignWhenOnlyBaitsWereStaged(t *testing.T) {
	w := newWorld(t, false)
	a := w.run(t, true)
	if a.Answer != alerts.AnswerNoSign {
		t.Fatalf("answer = %s: %s %v %v", a.Answer, a.Headline, a.Unsure, a.Leads)
	}
}

func TestRunNotHeldIsALead(t *testing.T) {
	w := newWorld(t, true)
	a := w.run(t, false)
	if a.Answer != alerts.AnswerUnknown {
		t.Fatalf("answer = %s: %s", a.Answer, a.Headline)
	}
	if len(a.Leads) == 0 || !strings.Contains(a.Leads[0], "byte-for-byte copy of your Chrome") {
		t.Errorf("leads = %q", a.Leads)
	}
}

func TestRunWithoutService(t *testing.T) {
	w := newWorld(t, false)
	c := Case{AlertID: "a", PID: 900, BaitAt: time.Now(), Stores: []baits.Store{w.store}}
	a := Run(c, Hooks{StartedAt: func(uint32) (time.Time, error) { return w.start, nil }})
	if a.Answer != alerts.AnswerUnknown || !strings.Contains(a.Headline, "flight recorder") {
		t.Errorf("answer %s: %s", a.Answer, a.Headline)
	}
}
