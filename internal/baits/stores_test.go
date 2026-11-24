package baits

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

func storeUser(t *testing.T) config.UserInfo {
	home := t.TempDir()
	u := config.UserInfo{Name: "u", Profile: home, Desktop: filepath.Join(home, "Desktop"), Documents: filepath.Join(home, "Documents"),
		Downloads: filepath.Join(home, "Downloads"), Variant: "0123456789abcdef"}
	switch runtime.GOOS {
	case "darwin":
		u.RoamingAppData = filepath.Join(home, "Library", "Application Support")
		u.LocalAppData = u.RoamingAppData
	case "linux":
		u.RoamingAppData, u.LocalAppData = filepath.Join(home, ".config"), filepath.Join(home, ".local", "share")
	default:
		u.RoamingAppData, u.LocalAppData = filepath.Join(home, "AppData", "Roaming"), filepath.Join(home, "AppData", "Local")
	}
	return u
}

func find(stores []Store, id string) (Store, bool) {
	for _, s := range stores {
		if s.ID == id {
			return s, true
		}
	}
	return Store{}, false
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRealBrowserStoreSkipsTheBaitProfile(t *testing.T) {
	u := storeUser(t)
	stores := RealStores(u, nil)
	chrome, ok := find(stores, "chrome-profile")
	if !ok {
		t.Fatal("no real Chrome store")
	}
	if chrome.Kind != StoreBrowser || chrome.Name != "your Chrome" {
		t.Errorf("chrome store = %+v", chrome)
	}
	spec, _ := ByID("chrome-profile")
	ud := spec.Inside(u)
	real := filepath.Join(ud, "Default", "Login Data")
	if !chrome.Matches(real) {
		t.Errorf("real Login Data not matched: %s", real)
	}
	if !chrome.Matches(filepath.Join(ud, "Profile 1", "Network", "Cookies")) {
		t.Error("cookies of a second profile not matched")
	}
	if !chrome.Matches(filepath.Join(ud, "Local State")) {
		t.Error("Local State (the key) not matched")
	}
	bait := filepath.Join(ud, ProfileFolder(u, "chrome-profile"), "Login Data")
	if chrome.Matches(bait) {
		t.Errorf("the bait profile's Login Data counts as real: %s", bait)
	}
	if chrome.Matches(filepath.Join(ud, "Default", "History")) {
		t.Error("History isn't one of the secrets")
	}
	if chrome.Matches(filepath.Join(ud, "Default", "Login Data-journal")) {
		t.Error("a journal file isn't the store")
	}

	touch(t, real)
	touch(t, bait)
	touch(t, filepath.Join(ud, "Default", "History"))
	got := chrome.Resolve()
	if len(got) != 1 || got[0] != real {
		t.Errorf("Resolve = %v, want only %s", got, real)
	}
}

func TestPlantedDecoyIsNotARealStore(t *testing.T) {
	u := storeUser(t)
	if _, ok := find(RealStores(u, map[string]bool{"exodus": true}), "exodus"); ok {
		t.Error("a planted Exodus decoy was listed as your real wallet")
	}
	ex, ok := find(RealStores(u, nil), "exodus")
	if !ok {
		t.Fatal("real Exodus not listed when no decoy is planted")
	}
	if ex.Kind != StoreWallet {
		t.Errorf("kind = %s", ex.Kind)
	}
	if !ex.Matches(filepath.Join(ex.Root, "exodus.wallet", "seed.seco")) {
		t.Errorf("seed.seco not matched; files %v", ex.Files)
	}
}

func TestLevelDBNamesAreLeftOpen(t *testing.T) {
	u := storeUser(t)
	d, ok := find(RealStores(u, nil), "discord")
	if !ok {
		t.Fatal("no real Discord store")
	}
	if d.Kind != StoreSession {
		t.Errorf("kind = %s", d.Kind)
	}
	if !d.Matches(filepath.Join(d.Root, "Local Storage", "leveldb", "000137.ldb")) {
		t.Errorf("a real LevelDB file isn't matched; files %v", d.Files)
	}
}

func TestSSHPublicKeysAreNotSecrets(t *testing.T) {
	u := storeUser(t)
	s, ok := find(RealStores(u, nil), "ssh")
	if !ok {
		t.Fatal("no ssh store")
	}
	if !s.Matches(filepath.Join(u.Profile, ".ssh", "id_ed25519")) {
		t.Error("private key not matched")
	}
	if s.Matches(filepath.Join(u.Profile, ".ssh", "id_ed25519.pub")) {
		t.Error("public key matched")
	}
	if s.Matches(filepath.Join(u.Profile, ".ssh", "known_hosts")) {
		t.Error("known_hosts matched")
	}
}

func TestStoreForAndDedupe(t *testing.T) {
	u := storeUser(t)
	stores := RealStores(u, nil)
	seen := map[string]int{}
	for _, s := range stores {
		seen[strings.ToLower(s.Root)]++
		if len(s.Files) == 0 {
			t.Errorf("store %s has no files", s.ID)
		}
	}
	for r, n := range seen {
		if n > 1 {
			t.Errorf("%d stores for %s", n, r)
		}
	}
	if _, ok := StoreFor(stores, filepath.Join(u.Profile, "Documents", "notes.txt")); ok {
		t.Error("an ordinary document is a store")
	}
}

func TestMatchRel(t *testing.T) {
	cases := []struct {
		pat, rel string
		prefix   bool
		want     bool
	}{
		{"*/Login Data", "Default/Login Data", false, true},
		{"*/Login Data", "Login Data", false, false},
		{"*/Login Data", "Default/x/Login Data", false, false},
		{"Profile 23", "Profile 23/Login Data", true, true},
		{"Profile 23", "Profile 2/Login Data", true, false},
		{"*.pub", "id_rsa.pub", true, true},
	}
	for _, c := range cases {
		if got := matchRel(c.pat, c.rel, c.prefix); got != c.want {
			t.Errorf("matchRel(%q, %q, %v) = %v", c.pat, c.rel, c.prefix, got)
		}
	}
}

func TestPrefixes(t *testing.T) {
	s := Store{Root: filepath.FromSlash("/u/Library"), Files: []string{"Cookies/Cookies.binarycookies", "Containers/com.apple.Safari/*/Cookies", "Keychains/login.keychain-db"}}
	got := s.Prefixes()
	want := []string{filepath.FromSlash("/u/Library/Containers/com.apple.Safari/"), filepath.FromSlash("/u/Library/Cookies/Cookies.binarycookies"), filepath.FromSlash("/u/Library/Keychains/login.keychain-db")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q", got)
	}
	c := Store{Root: filepath.FromSlash("/u/Chrome"), Files: []string{"Local State", "*/Login Data", "*/Network/Cookies"}}
	if got := c.Prefixes(); len(got) != 1 || got[0] != filepath.FromSlash("/u/Chrome/") {
		t.Errorf("chrome: %q", got)
	}
}

func TestDirsLeaveOutBaitFolders(t *testing.T) {
	u := storeUser(t)
	chrome, _ := find(RealStores(u, nil), "chrome-profile")
	spec, _ := ByID("chrome-profile")
	ud := spec.Inside(u)
	touch(t, filepath.Join(ud, "Local State"))
	touch(t, filepath.Join(ud, "Default", "Network", "Cookies"))
	touch(t, filepath.Join(ud, ProfileFolder(u, "chrome-profile"), "Login Data"))
	got := chrome.Dirs()
	want := []string{ud, filepath.Join(ud, "Default"), filepath.Join(ud, "Default", "Network")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("Dirs = %q\nwant %q", got, want)
	}
}
