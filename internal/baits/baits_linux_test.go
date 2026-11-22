package baits

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// The catalog has to hold together on any system: unique IDs, files under
// the user's own folders, and nothing that real tools read by themselves.
func TestLinuxCatalog(t *testing.T) {
	u := config.UserInfo{SID: "1000", Name: "u", Profile: "/home/u", Desktop: "/home/u/Desktop", Documents: "/home/u/Documents",
		Downloads: "/home/u/Downloads", RoamingAppData: "/home/u/.config", LocalAppData: "/home/u/.local/share", Variant: "0123456789abcdef",
		Embedded: map[string]string{}}
	never := map[string]bool{
		"/home/u/.aws/credentials": true, "/home/u/.aws/config": true, "/home/u/.npmrc": true, "/home/u/.netrc": true,
		"/home/u/.kube/config": true, "/home/u/.docker/config.json": true, "/home/u/.pypirc": false,
		"/home/u/.config/gcloud/application_default_credentials.json": true,
		"/home/u/.ssh/id_rsa": true, "/home/u/.ssh/id_ed25519": true, "/home/u/.ssh/id_ecdsa": true, "/home/u/.ssh/config": true,
		"/home/u/.ssh/known_hosts": true, "/home/u/.ssh/authorized_keys": true, "/home/u/.gitconfig": true, "/home/u/.bash_history": true,
	}
	seen := map[string]bool{}
	audited := 0
	for _, s := range Catalog {
		if seen[s.ID] {
			t.Errorf("bait ID %s is used twice", s.ID)
		}
		seen[s.ID] = true
		for _, f := range s.Files(u) {
			if !filepath.IsAbs(f.Path) || len(f.Path) < len("/home/u/") || f.Path[:8] != "/home/u/" {
				t.Errorf("%s: %s is outside the user's folders", s.ID, f.Path)
			}
			if never[f.Path] {
				t.Errorf("%s: %s is a file real tools read by themselves: never fake it", s.ID, f.Path)
			}
			if filepath.Ext(f.Path) == ".pub" {
				t.Errorf("%s: no public key next to a fake private one (the desktop keyring would load the pair)", s.ID)
			}
			if f.Audit {
				audited++
			}
			if f.Gen == nil {
				t.Errorf("%s: %s has no content", s.ID, f.Path)
			}
		}
	}
	for _, id := range []string{"home-passwords", "vivaldi", "chrome-profile", "electrum", "ssh-key", "git-credentials", "aws", "gcloud"} {
		if !seen[id] {
			t.Errorf("the starter set should have %s", id)
		}
	}
	if audited < 15 {
		t.Errorf("only %d watched files in the catalog", audited)
	}
	// Generated content is what it claims to be.
	g := NewGen()
	if b := genGcloudCredentials(g); string(b[:15]) != "SQLite format 3" {
		t.Error("gcloud's credentials.db should be an SQLite database")
	}
	if b := genGitCredentials(g); len(b) == 0 || b[len(b)-1] != '\n' {
		t.Error("git-credentials: one URL per line")
	}
	if b := genAWSBackup(g); len(b) == 0 || containsCR(b) {
		t.Error("the AWS backup should have Linux line endings")
	}
}

func containsCR(b []byte) bool {
	for _, c := range b {
		if c == '\r' {
			return true
		}
	}
	return false
}

// Planting happens with the rights of the folder's owner, not root's: the
// bait belongs to the user, and a link a program planted in the way can't
// lead root's writes anywhere else. Needs root and ABA_TEST_USER.
func TestPlantingAsTheOwner(t *testing.T) {
	name := os.Getenv("ABA_TEST_USER")
	if os.Getenv("ABA_INTEGRATION") != "1" || os.Geteuid() != 0 || name == "" {
		t.Skip("set ABA_INTEGRATION=1 and ABA_TEST_USER, as root, to run")
	}
	usr, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(usr.Uid)
	gid, _ := strconv.Atoi(usr.Gid)
	home, err := os.MkdirTemp("", "aba-home-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	os.Chmod(home, 0o755)
	os.Chown(home, uid, gid)
	owner := func(p string) (int, os.FileMode) {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return int(fi.Sys().(*syscall.Stat_t).Uid), fi.Mode().Perm()
	}
	g := NewGen()
	info := config.UserInfo{SID: usr.Uid, Profile: home}

	// A document: the user's, readable like its neighbours.
	doc := filepath.Join(home, "passwords.txt")
	bs, err := Create(CustomSpec("custom-doc", doc), info, g)
	if err != nil || len(bs.Files) != 1 {
		t.Fatalf("Create: %v (%+v)", err, bs)
	}
	if o, m := owner(doc); o != uid || m != 0o644 {
		t.Errorf("%s: owner %d mode %o, want %d 644", doc, o, m, uid)
	}

	// App data under a hidden folder: private, folders included.
	db := filepath.Join(home, ".config", "vivaldi", "Default", "Login Data")
	bs2, err := Create(CustomSpec("custom-db", db), info, g)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if o, m := owner(db); o != uid || m != 0o600 {
		t.Errorf("%s: owner %d mode %o, want %d 600", db, o, m, uid)
	}
	for _, d := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "vivaldi", "Default")} {
		if o, m := owner(d); o != uid || m != 0o700 {
			t.Errorf("%s: owner %d mode %o, want %d 700", d, o, m, uid)
		}
	}

	// The trap: a folder on the bait's path swapped for a link into a place
	// that's root's.
	victim, err := os.MkdirTemp("", "aba-victim-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(victim)
	os.Chmod(victim, 0o755)
	trap := filepath.Join(home, ".mozilla")
	if err := os.Symlink(victim, trap); err != nil {
		t.Fatal(err)
	}
	os.Lchown(trap, uid, gid)
	if _, err := Create(CustomSpec("custom-trap", filepath.Join(trap, "firefox", "logins.json")), info, g); err == nil {
		t.Error("planting through a link into root's folder should fail")
	}
	if ents, _ := os.ReadDir(victim); len(ents) != 0 {
		t.Errorf("root wrote into the folder the link pointed at: %v", ents)
	}

	// And this thread is root again afterwards.
	if err := os.WriteFile(filepath.Join(victim, "root-can"), []byte("x"), 0o600); err != nil {
		t.Errorf("root's own rights didn't come back: %v", err)
	}

	for _, b := range []*config.BaitState{bs, bs2} {
		if err := Remove(b); err != nil {
			t.Errorf("Remove: %v", err)
		}
	}
	for _, p := range []string{doc, db, filepath.Join(home, ".config")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s should be gone after Remove", p)
		}
	}
}

// A fake profile inside a real Firefox: a folder profiles.ini doesn't list,
// which Firefox therefore never opens. Once profiles.ini lists it, Firefox
// has taken it as its own (adopted), and the bait has to go.
func TestFirefoxProfileInside(t *testing.T) {
	home := t.TempDir()
	u := config.UserInfo{Profile: home, RoamingAppData: filepath.Join(home, ".config"), Embedded: map[string]string{}}
	s, ok := ByID("firefox-profile")
	if !ok {
		t.Fatal("no firefox-profile bait")
	}
	root := s.Inside(u)
	os.MkdirAll(filepath.Join(root, "abcd1234.default-release"), 0o700)
	os.WriteFile(filepath.Join(root, "profiles.ini"), []byte("[Profile0]\nName=default-release\nIsRelative=1\nPath=abcd1234.default-release\nDefault=1\n"), 0o600)
	name := FreeProfile(s, u)
	if name == "abcd1234.default-release" || !strings.HasSuffix(name, ".default-release-1") || len(name) != len("abcd1234.default-release-1") {
		t.Fatalf("FreeProfile = %q", name)
	}
	u.Embedded[s.ID] = name
	files := s.Files(u)
	if len(files) == 0 || filepath.Dir(files[0].Path) != filepath.Join(root, name) {
		t.Fatalf("files %+v, want them in %s", files, filepath.Join(root, name))
	}
	if Adopted(s, u) {
		t.Fatal("adopted before profiles.ini lists it")
	}
	f, _ := os.OpenFile(filepath.Join(root, "profiles.ini"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n[Profile1]\nName=work\nIsRelative=1\nPath=" + name + "\n")
	f.Close()
	if !Adopted(s, u) {
		t.Fatal("profiles.ini lists it, but it isn't seen as adopted")
	}
}
