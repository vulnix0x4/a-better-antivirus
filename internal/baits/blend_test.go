package baits

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// Creating "Discord\Update.exe" takes no admin rights. An empty or unsigned
// file there used to make ABA retire its Discord decoy within five minutes:
// plant a handful of those, wait, and most tripwires removed themselves.
func TestFakeAppMarkerIsNotAnInstall(t *testing.T) {
	u := testUser(t)
	real := Genuine
	defer func() { Genuine = real }()
	Genuine = func(path, signer string) bool { return false } // nothing here is signed
	marker := filepath.Join(u.LocalAppData, "Discord", "Update.exe")
	os.MkdirAll(filepath.Dir(marker), 0o755)
	os.WriteFile(marker, []byte("pretend app"), 0o644)
	discord, _ := ByID("discord")

	m, genuine := Installed(discord, u)
	if m != marker || genuine {
		t.Fatalf("Installed = %q, %v; want the marker, not genuine", m, genuine)
	}
	// A decoy that's already planted stays available (it isn't taken away at
	// the next `aba configure`)...
	for _, a := range Plan(u, map[string]bool{"discord": true}) {
		if a.Spec.ID == "discord" && !a.Available {
			t.Fatalf("a fake marker made the planted decoy unavailable: %s", a.Reason)
		}
	}
	// ...but nothing new is planted over what might be a real, unsigned build.
	for _, a := range Plan(u, nil) {
		if a.Spec.ID == "discord" && a.Available {
			t.Fatal("planting over a possible real install")
		}
	}
	// Signed by the publisher: that's the app.
	Genuine = func(path, signer string) bool { return signer == "Discord" }
	if m, genuine := Installed(discord, u); m != marker || !genuine {
		t.Fatalf("genuine install not recognised: %q, %v", m, genuine)
	}
	// Program Files takes admin rights to write to, so anything there counts.
	Genuine = func(path, signer string) bool { return false }
	fz, _ := ByID("filezilla")
	pfMarker := fz.Markers(u)[0]
	os.MkdirAll(filepath.Dir(pfMarker), 0o755)
	os.WriteFile(pfMarker, nil, 0o644)
	if _, genuine := Installed(fz, u); !genuine {
		t.Fatal("an app in Program Files should count as installed")
	}
	if dirs := OwnerDirs(discord, u); len(dirs) == 0 || dirs[0] != filepath.Join(u.LocalAppData, "Discord") {
		t.Fatalf("OwnerDirs = %v", dirs)
	}
}

// Every marker must be a file with a publisher to check: a folder anyone can
// create, or an app without a known signer, would bring the bypass back.
func TestEveryMarkerCanBeVerified(t *testing.T) {
	u := testUser(t)
	for _, s := range Catalog {
		if s.Markers == nil {
			continue
		}
		if s.Signer == "" {
			t.Errorf("%s has markers but no signer to verify them against", s.ID)
		}
		for _, m := range s.Markers(u) {
			if !strings.HasSuffix(strings.ToLower(m), ".exe") {
				t.Errorf("%s: marker %s isn't an executable", s.ID, m)
			}
		}
	}
}

// Without per-install names, skipping the baits is a list of file names.
func TestBaitNamesDifferPerInstall(t *testing.T) {
	u := testUser(t)
	paths := func(u config.UserInfo) map[string]string {
		out := map[string]string{}
		for _, s := range Catalog {
			for i, f := range s.Files(u) {
				out[s.ID+"/"+string(rune('0'+i))] = f.Path
			}
		}
		return out
	}
	// An install from before this existed keeps exactly the names it has.
	legacy := paths(u)
	for id, want := range map[string]string{
		"desktop-passwords/0": filepath.Join(u.Desktop, "passwords.txt"),
		"seed-phrase/0":       filepath.Join(u.Documents, "wallet recovery phrase.txt"),
		"backup-codes/0":      filepath.Join(u.Documents, "google backup codes.txt"),
		"keepass/0":           filepath.Join(u.Documents, "Passwords.kdbx"),
		"discord/0":           filepath.Join(u.RoamingAppData, `discord\Local Storage\leveldb\000005.ldb`),
		"firefox/1":           filepath.Join(u.RoamingAppData, `Mozilla\Firefox\Profiles\q8m3kx2v.default-release\logins.json`),
	} {
		if legacy[id] != want {
			t.Errorf("legacy name changed: %s = %q, want %q (an upgrade would orphan the planted bait)", id, legacy[id], want)
		}
	}
	// With a variant: stable for that install, different between installs.
	a, b := u, u
	a.Variant, b.Variant = "0123456789abcdef", "fedcba9876543210"
	pa, pa2, pb := paths(a), paths(a), paths(b)
	differ := 0
	for id := range pa {
		if pa[id] != pa2[id] {
			t.Fatalf("%s isn't stable for one install: %q vs %q", id, pa[id], pa2[id])
		}
		if pa[id] != pb[id] {
			differ++
		}
	}
	if differ < 4 {
		t.Errorf("only %d bait paths differ between two installs", differ)
	}
	// Whatever name is picked still has to be something a file grabber takes.
	tempting := regexp.MustCompile(`(?i)pass|seed|wallet|recovery|backup|2fa|codes|kdbx`)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		v := u
		v.Variant = strings.Repeat(string(rune('a'+i%26)), 3) + string(rune('0'+i%10)) + string(rune('A'+i/26))
		for _, id := range []string{"home-passwords", "documents-passwords", "desktop-passwords", "seed-phrase", "backup-codes", "keepass"} {
			s, _ := ByID(id)
			name := filepath.Base(s.Files(v)[0].Path)
			seen[id+"|"+name] = true
			if !tempting.MatchString(name) {
				t.Fatalf("%s: %q isn't a name a grabber looks for", id, name)
			}
		}
		ff, _ := ByID("firefox")
		if prof := filepath.Base(filepath.Dir(ff.Files(v)[1].Path)); !regexp.MustCompile(`^[a-z0-9]{8}\.default-release$`).MatchString(prof) {
			t.Fatalf("firefox profile name %q doesn't look like one", prof)
		}
		d, _ := ByID("discord")
		if n := filepath.Base(d.Files(v)[0].Path); !regexp.MustCompile(`^\d{6}\.ldb$`).MatchString(n) {
			t.Fatalf("leveldb file name %q doesn't look like one", n)
		}
	}
	if len(seen) < 20 {
		t.Errorf("only %d distinct file-bait names over 200 installs", len(seen))
	}
}

func times(t *testing.T, path string) (created, accessed, written time.Time) {
	t.Helper()
	var d windows.Win32FileAttributeData
	p, _ := windows.UTF16PtrFromString(path)
	if err := windows.GetFileAttributesEx(p, windows.GetFileExInfoStandard, (*byte)(unsafePointer(&d))); err != nil {
		t.Fatal(err)
	}
	return time.Unix(0, d.CreationTime.Nanoseconds()), time.Unix(0, d.LastAccessTime.Nanoseconds()), time.Unix(0, d.LastWriteTime.Nanoseconds())
}

// A folder listing shows a file's dates without opening it. A planted bait
// used to have all three dates identical to the tick, inside a folder created
// a moment ago: easy to tell from the real thing without tripping anything.
func TestPlantedFilesLookUsed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "discord")
	leveldb := filepath.Join(root, "Local Storage", "leveldb")
	os.MkdirAll(leveldb, 0o755)
	files := []string{filepath.Join(leveldb, "000005.ldb"), filepath.Join(leveldb, "CURRENT"), filepath.Join(root, "settings.json")}
	now := time.Now()
	for _, f := range files {
		os.WriteFile(f, []byte("x"), 0o644)
		ageFile(f)
		c, a, w := times(t, f)
		if !c.Before(now.Add(-29 * 24 * time.Hour)) {
			t.Errorf("%s: created %v, should be at least a month ago", f, c)
		}
		if !c.Before(w) || w.After(a) || a.After(now) {
			t.Errorf("%s: want created < modified <= opened <= now, got %v / %v / %v", f, c, w, a)
		}
		if c.Equal(w) || w.Equal(a) {
			t.Errorf("%s: identical timestamps give a planted file away: %v / %v / %v", f, c, w, a)
		}
	}
	ageTree(root, "")
	for _, dir := range []string{root, filepath.Join(root, "Local Storage"), leveldb} {
		dc, _, _ := times(t, dir)
		filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
			if err != nil || p == dir {
				return nil
			}
			if c, _, _ := times(t, p); c.Before(dc) {
				t.Errorf("%s (created %v) is older than the folder it's in, %s (created %v)", p, c, dir, dc)
			}
			return nil
		})
		if !dc.Before(now.Add(-29 * 24 * time.Hour)) {
			t.Errorf("folder %s looks brand new (created %v)", dir, dc)
		}
	}
}

// Baits take the indexing setting of the folder they're in, like any file
// created there. (They used to be the only "don't index" files in Documents.)
func TestIndexingMatchesTheFolder(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "passwords.txt")
	os.WriteFile(f, []byte("x"), 0o644)
	attrs := func(p string) uint32 {
		u, _ := windows.UTF16PtrFromString(p)
		a, err := windows.GetFileAttributes(u)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	set := func(p string, on bool) {
		u, _ := windows.UTF16PtrFromString(p)
		a := attrs(p) &^ windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
		if on {
			a |= windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
		}
		if err := windows.SetFileAttributes(u, a); err != nil {
			t.Fatal(err)
		}
	}
	const noIndex = windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	set(dir, false)
	set(f, true) // what older versions did
	indexedLikeFolder(f)
	if attrs(f)&noIndex != 0 {
		t.Fatal("a bait in an indexed folder is still marked \"don't index\"")
	}
	set(dir, true) // e.g. AppData
	indexedLikeFolder(f)
	if attrs(f)&noIndex == 0 {
		t.Fatal("a bait in a non-indexed folder should match it")
	}
}

func unsafePointer(d *windows.Win32FileAttributeData) unsafe.Pointer { return unsafe.Pointer(d) }

// An install made by an older version, after the upgrade: the baits it
// planted are brought in line without ABA then thinking someone changed them.
func TestBlendUpgradesAnOlderInstall(t *testing.T) {
	u := testUser(t)
	u.DecoyBrowser = "vivaldi"
	viv, _ := ByID("vivaldi")
	g := NewGen()
	bs := &config.BaitState{ID: "vivaldi", Status: "ok"}
	// What v0.5 planted: an empty one-page database (and small text files),
	// every date identical, in folders made that same minute.
	old := time.Now().Add(-90 * 24 * time.Hour).Truncate(time.Second)
	empty := make([]byte, legacyEmptyDB)
	copy(empty, "SQLite format 3\x00")
	for _, f := range viv.Files(u) {
		os.MkdirAll(filepath.Dir(f.Path), 0o755)
		data := []byte(`{"profile":{}}`)
		if strings.HasSuffix(f.Path, "Login Data") || strings.HasSuffix(f.Path, "Cookies") || strings.HasSuffix(f.Path, "Web Data") {
			data = empty
		}
		os.WriteFile(f.Path, data, 0o644)
		setTimes(f.Path, old, old, old)
		fi, _ := os.Stat(f.Path)
		bs.Files = append(bs.Files, config.BaitFile{Path: f.Path, Created: true, Size: fi.Size(), ModTime: fi.ModTime()})
	}
	bs.CreatedDirs = []string{filepath.Join(u.LocalAppData, "Vivaldi")}

	if !Blend(bs, viv, u, g) {
		t.Fatal("nothing was upgraded")
	}
	for _, f := range bs.Files {
		fi, err := os.Stat(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != f.Size || !fi.ModTime().Equal(f.ModTime) {
			t.Errorf("%s: the record wasn't updated, so the health check would report it as modified", f.Path)
		}
		c, a, w := times(t, f.Path)
		if c.Equal(w) || w.Equal(a) {
			t.Errorf("%s: still has identical timestamps", f.Path)
		}
		if strings.HasSuffix(f.Path, "Login Data") {
			if fi.Size() <= legacyEmptyDB {
				t.Errorf("Login Data is still an empty database (%d bytes)", fi.Size())
			}
			b, _ := os.ReadFile(f.Path)
			if !strings.Contains(string(b), "CREATE TABLE logins") {
				t.Error("Login Data has no logins table")
			}
		}
	}
	root := bs.CreatedDirs[0]
	rc, _, _ := times(t, root)
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && p != root {
			if c, _, _ := times(t, p); c.Before(rc) {
				t.Errorf("%s is older than the decoy's folder", p)
			}
		}
		return nil
	})
	// A second pass has nothing left to do, and leaves the files alone.
	before, _ := os.Stat(bs.Files[1].Path)
	if Blend(bs, viv, u, g) {
		t.Error("blending twice changed something again")
	}
	if after, _ := os.Stat(bs.Files[1].Path); !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Error("a second pass rewrote a file")
	}
	// A file the real app (or you) has written to since is never touched.
	mine := bs.Files[0].Path
	os.WriteFile(mine, []byte("the real app's data now"), 0o644)
	Blend(bs, viv, u, g)
	if b, _ := os.ReadFile(mine); string(b) != "the real app's data now" {
		t.Fatal("Blend rewrote a file that was no longer ABA's")
	}
}
