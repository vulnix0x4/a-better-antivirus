package baits

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// A bait the way the catalog's document baits are made: one file in dir,
// named from a pool.
func pooled(dir string) Spec {
	return Spec{
		ID: "doc", Name: "a document", Kind: KindFile,
		Files: func(u config.UserInfo) []FileSpec {
			name, alt := varyFile(u, "doc", "Passwords.kdbx", "Database.kdbx", "keepass.kdbx")
			return []FileSpec{{Path: j(dir, name), Alt: alt, Text: true, Gen: genPasswordsTxt}}
		},
	}
}

const yours = "my real passwords, not a bait"

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The name this install would use is already a file of yours: the bait gets
// another name of its pool, the choice sticks, and your file is not touched.
func TestBaitTakesAnotherNameWhenYoursIsThere(t *testing.T) {
	dir := t.TempDir()
	s := pooled(dir)
	u := config.UserInfo{Variant: "a1b2c3"}
	mine := s.Files(u)[0].Path
	write(t, mine, yours)

	shared := config.UserInfo{Variant: u.Variant, Names: map[string]string{"other": "x"}}
	if in := Settle(s, &u, nil); len(in) != 0 {
		t.Fatalf("still in the way: %v", in)
	}
	got := s.Files(u)[0].Path
	if got == mine {
		t.Fatalf("the bait would still be your file %s", mine)
	}
	if _, err := os.Lstat(got); err == nil {
		t.Fatalf("%s is there already", got)
	}
	if u.Names["doc"] != filepath.Base(got) {
		t.Fatalf("the name isn't kept: %v", u.Names)
	}
	// Settling again changes nothing: the new name is free.
	if Settle(s, &u, nil); s.Files(u)[0].Path != got {
		t.Fatal("the name moved again")
	}

	// Planting it leaves your file as it was.
	bs, err := create(s, u, NewGen())
	if err != nil || len(bs.Files) != 1 || !bs.Files[0].Created || bs.Files[0].Path != got {
		t.Fatalf("create: %v, %+v", err, bs)
	}
	if b, _ := os.ReadFile(mine); string(b) != yours {
		t.Fatalf("your file was changed: %q", b)
	}

	// A config's map isn't written to through a copy of its user (Plan
	// settles on a copy to see whether a bait fits).
	cp := shared
	write(t, s.Files(cp)[0].Path, yours)
	Settle(s, &cp, nil)
	if _, ok := shared.Names["doc"]; ok || cp.Names["doc"] == "" || cp.Names["other"] != "x" {
		t.Fatalf("copy %v, original %v", cp.Names, shared.Names)
	}
}

// Every name of the pool is a file of yours: the bait isn't planted at all.
func TestBaitIsLeftOutWhenEveryNameIsYours(t *testing.T) {
	dir := t.TempDir()
	s := pooled(dir)
	u := config.UserInfo{Variant: "a1b2c3"}
	for _, n := range s.Files(u)[0].Alt.Pool {
		write(t, j(dir, n), yours)
	}
	in := Settle(s, &u, nil)
	if len(in) != 1 || len(u.Names) != 0 {
		t.Fatalf("in the way %v, names %v", in, u.Names)
	}
	// And if it comes to planting all the same, your file is not taken over:
	// no bait on record, nothing written, nothing of it kept.
	bs, err := create(s, u, NewGen())
	if err == nil || len(bs.Files) != 0 {
		t.Fatalf("your file became a bait: %v, %+v", err, bs)
	}
	if b, _ := os.ReadFile(in[0]); string(b) != yours {
		t.Fatalf("your file was changed: %q", b)
	}
}

// What's not in the way: ABA's own baits (a rename looks at names while the
// old baits are still there), and a bait of the original honeypot script,
// which is taken over as before.
func TestOwnAndLegacyBaitsAreNotInTheWay(t *testing.T) {
	dir := t.TempDir()
	s := pooled(dir)
	u := config.UserInfo{Variant: "a1b2c3"}
	p := s.Files(u)[0].Path
	write(t, p, "an ABA bait")
	if in := Settle(s, &u, map[string]bool{paths.Key(p): true}); len(in) != 0 || len(u.Names) != 0 {
		t.Fatalf("ABA's own bait counted as yours: %v %v", in, u.Names)
	}

	write(t, p, "login: "+legacyMarkers[0])
	if in := Settle(s, &u, nil); len(in) != 0 || len(u.Names) != 0 {
		t.Fatalf("a legacy bait counted as yours: %v %v", in, u.Names)
	}
	bs, err := create(s, u, NewGen())
	if err != nil || len(bs.Files) != 1 || !bs.Files[0].Created {
		t.Fatalf("legacy bait not taken over: %v, %+v", err, bs)
	}
}

// A bait you added yourself is the file you named, as it is.
func TestABaitYouAddedTakesYourFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notes.txt")
	write(t, p, yours)
	s := CustomSpec("custom-x", p)
	u := config.UserInfo{Variant: "a1b2c3"}
	if in := Settle(s, &u, nil); len(in) != 0 {
		t.Fatalf("in the way: %v", in)
	}
	// (Without the audit rule, which needs administrator rights.)
	s.Files = func(config.UserInfo) []FileSpec {
		return []FileSpec{{Path: p, Text: true, Gen: genPasswordsTxt}}
	}
	bs, err := create(s, u, NewGen())
	if err != nil || len(bs.Files) != 1 || bs.Files[0].Created || bs.Files[0].Text != yours {
		t.Fatalf("create: %v, %+v", err, bs)
	}
}

// The catalog: with a file of yours under every name a document bait could
// get, setup doesn't offer that bait; with one name free, it does, and under
// that name.
func TestPlanKeepsCatalogBaitsOffYourFiles(t *testing.T) {
	home := t.TempDir()
	u := config.UserInfo{
		Variant: "a1b2c3", Profile: home,
		Desktop: j(home, "Desktop"), Documents: j(home, "Documents"), Downloads: j(home, "Downloads"),
		LocalAppData: j(home, "AppData", "Local"), RoamingAppData: j(home, "AppData", "Roaming"),
	}
	for _, d := range []string{u.Desktop, u.Documents, u.Downloads, u.LocalAppData, u.RoamingAppData} {
		os.MkdirAll(d, 0o755)
	}
	var spec Spec
	for _, s := range Catalog {
		if s.Kind == KindFile && s.Files != nil && s.Inside == nil {
			if f := s.Files(u); len(f) == 1 && f[0].Alt != nil && filepath.Dir(f[0].Path) == u.Documents {
				spec = s
				break
			}
		}
	}
	if spec.ID == "" {
		t.Skip("no document bait with a pool of names in this catalog")
	}
	fits := func() Availability {
		for _, a := range Plan(u, nil) {
			if a.Spec.ID == spec.ID {
				return a
			}
		}
		t.Fatalf("%s isn't in the plan", spec.ID)
		return Availability{}
	}
	if a := fits(); !a.Available {
		t.Fatalf("%s doesn't fit an empty home: %s", spec.ID, a.Reason)
	}

	pool := spec.Files(u)[0].Alt.Pool
	for _, n := range pool {
		write(t, j(u.Documents, n), yours)
	}
	if a := fits(); a.Available || !strings.Contains(a.Reason, "already have a file") {
		t.Fatalf("offered on top of your files: %+v", a)
	}

	os.Remove(j(u.Documents, pool[len(pool)-1]))
	if a := fits(); !a.Available {
		t.Fatalf("one name is free, but: %s", a.Reason)
	}
	if Settle(spec, &u, nil); filepath.Base(spec.Files(u)[0].Path) != pool[len(pool)-1] {
		t.Fatalf("got %s, want the free name %s", spec.Files(u)[0].Path, pool[len(pool)-1])
	}
}
