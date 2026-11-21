package baits

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// realBrowser makes u look like someone who uses Chrome: the program in
// Program Files and a User Data folder with the given profiles registered.
func realBrowser(t *testing.T, u config.UserInfo, localState string, folders ...string) string {
	t.Helper()
	exe := filepath.Join(pf(), `Google\Chrome\Application\chrome.exe`)
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, nil, 0o644)
	ud := filepath.Join(u.LocalAppData, `Google\Chrome\User Data`)
	for _, f := range folders {
		os.MkdirAll(filepath.Join(ud, f), 0o755)
	}
	os.MkdirAll(ud, 0o755)
	os.WriteFile(filepath.Join(ud, "Local State"), []byte(localState), 0o644)
	return ud
}

func planOf(u config.UserInfo, ours map[string]bool) map[string]Availability {
	got := map[string]Availability{}
	for _, a := range Plan(u, ours) {
		got[a.Spec.ID] = a
	}
	return got
}

// A stealer that checks "is this browser really installed?" before touching
// its data never opens a decoy. A fake profile inside the real browser passes
// that check, so it's only planted where the real browser is.
func TestProfileBaitNeedsTheRealBrowser(t *testing.T) {
	u := testUser(t)
	if a := planOf(u, nil)["chrome-profile"]; a.Available {
		t.Fatal("no Chrome here: nothing to plant a profile into")
	}
	// The program without any data (never started) isn't enough either.
	exe := filepath.Join(pf(), `Google\Chrome\Application\chrome.exe`)
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, nil, 0o644)
	if a := planOf(u, nil)["chrome-profile"]; a.Available {
		t.Fatal("Chrome was never used: there's no profile data to sit next to")
	}
	ud := realBrowser(t, u, `{"profile":{"info_cache":{"Default":{},"Profile 1":{}},"profiles_created":2}}`, "Default", "Profile 1")
	got := planOf(u, nil)
	if !got["chrome-profile"].Available {
		t.Fatalf("Chrome is installed and used: %+v", got["chrome-profile"])
	}
	if got["edge-profile"].Available || got["brave-profile"].Available {
		t.Fatal("only Chrome is here")
	}
	// ABA's own fake Brave isn't a real browser to plant a profile into.
	u.DecoyBrowser = "brave"
	brave, _ := ByID("brave")
	for _, f := range brave.Files(u) {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		os.WriteFile(f.Path, []byte("{}"), 0o644)
	}
	if planOf(u, map[string]bool{"brave": true})["brave-profile"].Available {
		t.Fatal("a profile bait was offered inside ABA's own decoy browser")
	}

	spec, _ := ByID("chrome-profile")
	u.Embedded = map[string]string{"chrome-profile": FreeProfile(spec, u)}
	files := spec.Files(u)
	if !strings.HasPrefix(files[0].Path, ud+`\Profile `) || filepath.Base(files[0].Path) != "Login Data" {
		t.Fatalf("files: %s", files[0].Path)
	}
	if dirs := OwnerDirs(spec, u); len(dirs) != 3 || dirs[0] != filepath.Dir(exe) {
		t.Fatalf("the real Chrome's folders: %v", dirs)
	}
}

// The folder must be one the browser isn't using and won't get to soon:
// Chrome names a new profile after how many it has ever created.
func TestProfileBaitKeepsOutOfTheBrowsersWay(t *testing.T) {
	u := testUser(t)
	ud := realBrowser(t, u, `{"profile":{"info_cache":{"Default":{},"Profile 1":{},"Profile 14":{}},"profiles_created":15}}`, "Default", "Profile 1", "Profile 14")
	spec, _ := ByID("chrome-profile")
	num := regexp.MustCompile(`^Profile (\d+)$`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		name := FreeProfile(spec, u)
		m := num.FindStringSubmatch(name)
		if m == nil {
			t.Fatalf("not a profile folder name: %q", name)
		}
		if n := atoi(m[1]); n < 15+8 {
			t.Fatalf("%q is one of the next profiles Chrome would create (it has made 15)", name)
		}
		if _, err := os.Stat(filepath.Join(ud, name)); err == nil {
			t.Fatalf("%q already exists", name)
		}
		seen[name] = true
	}
	if len(seen) < 8 {
		t.Errorf("only %d different folders over 200 picks: not a fixed name", len(seen))
	}
	// A browser that has only ever had "Default" (no counter in Local State).
	u2 := testUser(t)
	realBrowser(t, u2, `{"profile":{"info_cache":{"Default":{}}}}`, "Default")
	if m := num.FindStringSubmatch(FreeProfile(spec, u2)); m == nil || atoi(m[1]) < 12 {
		t.Fatalf("fresh browser: %v", m)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// If the browser does reach that folder and takes it as a profile of its own,
// ABA has to notice (and then gets out of its way).
func TestAdoptedProfileIsNoticed(t *testing.T) {
	u := testUser(t)
	ud := realBrowser(t, u, `{"profile":{"info_cache":{"Default":{}}}}`, "Default")
	spec, _ := ByID("chrome-profile")
	u.Embedded = map[string]string{"chrome-profile": "Profile 23"}
	if Adopted(spec, u) {
		t.Fatal("Chrome doesn't know Profile 23")
	}
	os.WriteFile(filepath.Join(ud, "Local State"), []byte(`{"profile":{"info_cache":{"Default":{},"Profile 23":{"name":"Work"}},"profiles_created":24}}`), 0o644)
	if !Adopted(spec, u) {
		t.Fatal("Chrome now lists Profile 23 as its own")
	}
	// A decoy for an app you don't have is never "adopted" this way.
	if discord, _ := ByID("discord"); Adopted(discord, u) {
		t.Fatal("only baits inside a real app can be adopted")
	}
	// Half-written or missing Local State: not adopted, no panic.
	os.WriteFile(filepath.Join(ud, "Local State"), []byte(`{"profile":{"info_ca`), 0o644)
	if Adopted(spec, u) {
		t.Fatal("unreadable Local State")
	}
}

// `aba bait rename` replants exactly the baits whose files moved.
func TestMovedTellsWhichBaitsToReplant(t *testing.T) {
	u := testUser(t)
	u.Variant = "0123456789abcdef"
	u.Embedded = map[string]string{"chrome-profile": "Profile 23"}
	state := func(id string) (*config.BaitState, Spec) {
		s, _ := ByID(id)
		bs := &config.BaitState{ID: id}
		for _, f := range s.Files(u) {
			bs.Files = append(bs.Files, config.BaitFile{Path: f.Path})
		}
		return bs, s
	}
	renamed := u
	renamed.Variant = "fedcba9876543210"
	moved := 0
	for _, id := range []string{"home-passwords", "documents-passwords", "desktop-passwords", "seed-phrase", "backup-codes", "keepass", "discord"} {
		bs, s := state(id)
		if Moved(bs, s, u) {
			t.Errorf("%s: nothing changed, yet it counts as moved", id)
		}
		if Moved(bs, s, renamed) {
			moved++
		}
	}
	if moved < 3 {
		t.Errorf("only %d of 7 baits got a new name", moved)
	}
	// Baits whose place doesn't depend on the names stay put.
	for _, id := range []string{"chrome-profile", "vivaldi", "telegram", "aws"} {
		if bs, s := state(id); Moved(bs, s, renamed) {
			t.Errorf("%s would be replanted for nothing", id)
		}
	}
}
