package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/instant"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// Does a real browser leave ABA's fake profile alone?
//
// The profile baits (baits.embeddedProfile) rest on one assumption: a
// Chromium browser only opens the profiles listed in its Local State, so a
// "Profile 23" folder it doesn't know is never touched by the browser
// itself. If that were wrong, every start of your browser would trip a bait.
//
// This runs the browsers installed on this PC against a fake profile and
// reports every open of its files. No admin rights needed (it watches with
// oplocks, like instant freeze does). Manual, because it starts browsers:
//
//	ABA_BROWSER_TEST=1 go test ./internal/integration -run Browser -v

type opens struct {
	mu   sync.Mutex
	seen []string
}

func (o *opens) add(what, path string, pids []uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	who := "someone it couldn't pin down"
	if len(pids) > 0 {
		var names []string
		for _, p := range pids {
			img, _ := procinfo.ImagePath(p)
			names = append(names, fmt.Sprintf("%s (pid %d)", filepath.Base(img), p))
		}
		who = strings.Join(names, ", ")
	}
	o.seen = append(o.seen, fmt.Sprintf("%s: %s by %s", what, path, who))
}

func (o *opens) list() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.seen...)
}

// plant writes a profile bait's files (without audit rules, which need admin)
// and guards them. It returns what gets opened, and a cleanup func.
func plant(t *testing.T, spec baits.Spec, u config.UserInfo) (*opens, func()) {
	t.Helper()
	g := baits.NewGen()
	var guarded []string
	var top string
	for _, f := range spec.Files(u) {
		if top == "" {
			top = filepath.Dir(f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.Path, f.Gen(g), 0o644); err != nil {
			t.Fatal(err)
		}
		if f.Audit {
			guarded = append(guarded, f.Path)
		}
	}
	o := &opens{}
	w := &instant.Watcher{Self: uint32(os.Getpid()),
		OnOpen: func(p string, _ time.Time, _ instant.Intent, pids []uint32) { o.add("opened", p, pids) },
		OnGhost: func(p string, _ time.Time, _ instant.Intent, pids []uint32, _ bool) {
			o.add("opened without waiting", p, pids)
		},
		OnOther: func(p string, access uint32) {
			o.add(fmt.Sprintf("opened (not for reading, access 0x%x)", access), p, nil)
		}}
	w.Sync(guarded)
	time.Sleep(300 * time.Millisecond)
	if w.Armed() != len(guarded) {
		t.Fatalf("only %d of %d files guarded", w.Armed(), len(guarded))
	}
	return o, func() {
		w.Stop()
		os.RemoveAll(top)
	}
}

func browserSpecs() []baits.Spec {
	var out []baits.Spec
	for _, id := range []string{"chrome-profile", "edge-profile", "brave-profile"} {
		s, _ := baits.ByID(id)
		out = append(out, s)
	}
	return out
}

func hostExe(s baits.Spec, u config.UserInfo) string {
	for _, p := range s.Host(u) {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// killUsing ends the browser processes started on a given data folder (and
// only those: your own browser windows use a different one).
func killUsing(dataDir string) {
	snap, err := procinfo.Snapshot()
	if err != nil {
		return
	}
	for pid := range snap {
		if cl, _ := procinfo.CommandLine(pid); strings.Contains(strings.ToLower(cl), strings.ToLower(dataDir)) && pid != uint32(os.Getpid()) {
			procinfo.Kill(pid)
		}
	}
}

// Part 1: a fresh, separate data folder per browser, so the browser can be
// started and stopped freely without touching your real profile or windows.
func TestBrowserLeavesAFakeProfileAloneAtStartup(t *testing.T) {
	if os.Getenv("ABA_BROWSER_TEST") != "1" {
		t.Skip("set ABA_BROWSER_TEST=1 to run (starts the browsers installed here, without windows)")
	}
	real, err := install.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	tested := 0
	for _, spec := range browserSpecs() {
		exe := hostExe(spec, real)
		if exe == "" {
			t.Logf("%s: not installed here", spec.ID)
			continue
		}
		// A stand-in user whose LocalAppData is a temp folder: the spec then
		// puts the browser's data folder (and the bait) in there.
		u := real
		u.LocalAppData = filepath.Join(t.TempDir(), "Local")
		u.Embedded = nil
		dataDir := spec.Inside(u)
		os.MkdirAll(dataDir, 0o755)
		run := func(seconds int, extra ...string) {
			args := append([]string{"--user-data-dir=" + dataDir, "--no-first-run", "--no-default-browser-check", "--headless=new", "--disable-gpu"}, extra...)
			c := exec.Command(exe, args...)
			if err := c.Start(); err != nil {
				t.Fatalf("%s: %v", exe, err)
			}
			time.Sleep(time.Duration(seconds) * time.Second)
			killUsing(dataDir)
			c.Process.Kill()
			c.Wait()
			time.Sleep(time.Second)
		}
		run(8, "about:blank") // first start: creates Local State and the Default profile
		if _, err := os.Stat(filepath.Join(dataDir, "Local State")); err != nil {
			t.Errorf("%s: the browser didn't set up %s: %v", spec.ID, dataDir, err)
			continue
		}
		u.Embedded = map[string]string{spec.ID: baits.FreeProfile(spec, u)}
		folder := filepath.Join(dataDir, u.Embedded[spec.ID])
		o, cleanup := plant(t, spec, u)
		before := listing(folder)
		run(15, "about:blank")                                        // an ordinary start, the fake profile sitting next to Default
		run(10, "--profile-directory=Default", "https://example.com") // and one that names a profile and loads a page
		after := listing(folder)
		adopted := baits.Adopted(spec, u)
		cleanup()
		tested++
		if got := o.list(); len(got) > 0 {
			t.Errorf("%s: the browser opened the fake profile's files:\n  %s", spec.ID, strings.Join(got, "\n  "))
		} else {
			t.Logf("%s: %s started twice with %s next to Default: none of its files were opened", spec.ID, filepath.Base(exe), u.Embedded[spec.ID])
		}
		if before != after {
			t.Errorf("%s: the browser changed the fake profile folder:\n before: %s\n after:  %s", spec.ID, before, after)
		}
		if adopted {
			t.Errorf("%s: the browser registered the fake folder as one of its profiles", spec.ID)
		}
	}
	if tested == 0 {
		t.Skip("no Chromium browser installed here")
	}
}

func listing(dir string) string {
	var parts []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			parts = append(parts, fmt.Sprintf("%s:%d", rel, fi.Size()))
		}
		return nil
	})
	return strings.Join(parts, " ")
}

// Part 2: the real thing. The fake profile goes into the data folder your
// browsers actually use, for a while, with whatever browser is running.
func TestRunningBrowsersLeaveAFakeProfileAlone(t *testing.T) {
	if os.Getenv("ABA_BROWSER_TEST") != "1" {
		t.Skip("set ABA_BROWSER_TEST=1 to run")
	}
	u, err := install.CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	watch := 60 * time.Second
	if s := os.Getenv("ABA_BROWSER_TEST_SECONDS"); s != "" {
		var n int
		fmt.Sscan(s, &n)
		watch = time.Duration(n) * time.Second
	}
	snap, _ := procinfo.Snapshot()
	running := map[string]int{}
	for _, e := range snap {
		running[strings.ToLower(e.Exe)]++
	}
	type planted struct {
		spec    baits.Spec
		o       *opens
		cleanup func()
		folder  string
		before  string
	}
	var all []planted
	u.Embedded = map[string]string{}
	for _, a := range baits.Plan(u, nil) {
		if a.Spec.Inside == nil || !a.Available {
			continue
		}
		u.Embedded[a.Spec.ID] = baits.FreeProfile(a.Spec, u)
		folder := filepath.Join(a.Spec.Inside(u), u.Embedded[a.Spec.ID])
		if _, err := os.Stat(folder); err == nil {
			t.Fatalf("%s already exists", folder)
		}
		o, cleanup := plant(t, a.Spec, u)
		defer cleanup()
		all = append(all, planted{a.Spec, o, cleanup, folder, listing(folder)})
		t.Logf("%s: planted %s (%d %s processes running)", a.Spec.ID, folder, running[strings.ToLower(a.Spec.OwnerExes[0])], a.Spec.OwnerExes[0])
	}
	if len(all) == 0 {
		t.Skip("no browser here to plant a profile into")
	}
	time.Sleep(watch)
	for _, p := range all {
		if got := p.o.list(); len(got) > 0 {
			t.Errorf("%s: something opened the fake profile within %v:\n  %s", p.spec.ID, watch, strings.Join(got, "\n  "))
		} else {
			t.Logf("%s: nothing opened it in %v", p.spec.ID, watch)
		}
		if after := listing(p.folder); after != p.before {
			t.Errorf("%s: the folder changed: %s -> %s", p.spec.ID, p.before, after)
		}
		if baits.Adopted(p.spec, u) {
			t.Errorf("%s: the browser registered the fake folder as a profile", p.spec.ID)
		}
	}
}
