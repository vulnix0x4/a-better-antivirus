package baits

// The real things the baits imitate.
//
// Every decoy in the catalog stands in for a real app's data, and every bait
// inside a real browser sits next to that browser's real profiles. So the
// catalog already knows where your real passwords, cookies, wallets and
// sessions are: next to the baits, or where a decoy would go if you didn't
// have the app. The flight recorder (package recorder) watches those real
// files, quietly, so that after a catch ABA can say whether the program that
// tripped a bait had already been at the real thing.
//
// Nothing here ever reads a real file. RealStores only names them; Resolve
// lists the ones that exist.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// Kinds of real store, for what to do about one that was read.
const (
	StoreBrowser = "browser" // saved passwords, cookies, the key that unlocks them
	StoreWallet  = "wallet"
	StoreSession = "session" // a logged-in app: Telegram, Discord
	StoreKeys    = "keys"    // SSH keys, cloud keys, saved git passwords, the system's password store
	StoreApp     = "app"     // other saved logins (FileZilla…)
)

// Store is one real app's secrets: a folder and the files in it that matter.
type Store struct {
	ID   string // the catalog ID it comes from, or a name of its own
	Name string // "your Chrome", "your Exodus wallet"
	Kind string
	Root string
	// Files are the files that matter, relative to Root, with "/" between
	// folders: "*" stands for any one folder or part of a name ("*/Login
	// Data" is Login Data in every profile).
	Files []string
	// Skip are folders under Root, in the same form, that hold baits (a fake
	// profile inside a real browser): never part of the real store.
	Skip []string
}

// chromiumSecrets are the files of a Chromium-family browser (Chrome, Edge,
// Brave…) that hold what stealers take, in every profile.
var chromiumSecrets = []string{
	"Local State", // the key that unlocks the passwords and cookies
	"*/Login Data", "*/Login Data For Account", "*/Ya Passman Data",
	"*/Cookies", "*/Network/Cookies",
	"*/Web Data", // saved cards and autofill
	"*/Local Extension Settings/" + metamaskID + "/*",
}

// firefoxSecrets are the same for Firefox, in every profile folder.
var firefoxSecrets = []string{"*/logins.json", "*/key4.db", "*/cookies.sqlite"}

// RealStores lists the real stores this person may have. planted lists the
// bait IDs that are planted now (not retired): a decoy that's planted means
// the real app isn't there, and its folder is fake.
func RealStores(u config.UserInfo, planted map[string]bool) []Store {
	var out []Store
	for _, s := range Catalog {
		var st Store
		var ok bool
		switch {
		case s.Inside != nil:
			st, ok = insideStore(s, u)
		case s.Root != nil && s.Kind != KindFile && !planted[s.ID]:
			st, ok = decoyStore(s, u)
		}
		if ok {
			out = append(out, st)
		}
	}
	out = append(out, extraStores(u)...)
	return dedupe(out)
}

// insideStore is the real browser a bait profile was (or would be) planted in.
func insideStore(s Spec, u config.UserInfo) (Store, bool) {
	root := s.Inside(u)
	if root == "" {
		return Store{}, false
	}
	st := Store{ID: s.ID, Name: "your " + strings.TrimPrefix(s.Name, "extra profile inside your "), Kind: StoreBrowser, Root: root}
	if s.profilesFile() == firefoxIndex {
		sub := ""
		if s.ProfileDir != "" {
			sub = filepath.ToSlash(s.ProfileDir) + "/"
		}
		for _, f := range firefoxSecrets {
			st.Files = append(st.Files, sub+f)
		}
		st.Skip = []string{sub + firefoxFolder(u, s.ID)}
		return st, true
	}
	st.Files = append([]string(nil), chromiumSecrets...)
	st.Skip = []string{ProfileFolder(u, s.ID)}
	return st, true
}

var seqName = regexp.MustCompile(`^\d{6}\.(log|ldb)$`)

// decoyStore is where the real app a decoy imitates keeps its data: the
// decoy's own files, with the parts that differ from one person to the next
// (the profile folder, LevelDB's numbered files) left open.
func decoyStore(s Spec, u config.UserInfo) (Store, bool) {
	root := s.Root(u)
	if root == "" {
		return Store{}, false
	}
	files := s.Files(u)
	if len(files) == 1 && paths.Same(files[0].Path, root) {
		root = filepath.Dir(root) // the store is a single file (~/.git-credentials)
	}
	st := Store{ID: s.ID, Name: "your " + s.Name, Kind: storeKind(s), Root: root}
	seen := map[string]bool{}
	for _, f := range files {
		if !f.Audit {
			continue
		}
		rel, err := filepath.Rel(root, f.Path)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for i, p := range parts {
			switch {
			case p == "Default" || p == firefoxProfile(u) || strings.HasSuffix(p, ".default-release") || strings.HasSuffix(p, ".default"):
				parts[i] = "*"
			case i == len(parts)-1 && seqName.MatchString(p):
				parts[i] = "*" + filepath.Ext(p)
			}
		}
		pat := strings.Join(parts, "/")
		if !seen[pat] {
			seen[pat] = true
			st.Files = append(st.Files, pat)
		}
	}
	if st.Kind == StoreBrowser {
		if strings.Contains(strings.ToLower(s.Name), "firefox") {
			st.Files = appendNew(st.Files, prefixed(st.Files, firefoxSecrets)...)
		} else {
			st.Files = appendNew(st.Files, prefixed(st.Files, chromiumSecrets)...)
		}
	}
	return st, len(st.Files) > 0
}

// prefixed puts the folder the decoy's own patterns are in ("User Data/",
// "Opera Stable/") in front of a browser's usual secrets.
func prefixed(have, secrets []string) []string {
	prefix := ""
	for _, h := range have {
		if i := strings.Index(h, "*/"); i > 0 {
			prefix = h[:i]
			break
		}
		if strings.HasSuffix(h, "Local State") && h != "Local State" {
			prefix = strings.TrimSuffix(h, "Local State")
			break
		}
	}
	out := make([]string, len(secrets))
	for i, s := range secrets {
		out[i] = prefix + s
	}
	return out
}

func appendNew(xs []string, add ...string) []string {
	for _, a := range add {
		found := false
		for _, x := range xs {
			found = found || x == a
		}
		if !found {
			xs = append(xs, a)
		}
	}
	return xs
}

func storeKind(s Spec) string {
	switch s.Category {
	case "Browsers":
		return StoreBrowser
	case "Wallets":
		return StoreWallet
	case "Credentials":
		return StoreKeys
	}
	switch s.ID {
	case "telegram", "discord":
		return StoreSession
	}
	return StoreApp
}

// dedupe keeps one store per folder: a browser both a decoy and a bait
// profile know about is listed once (the bait profile's, which knows its
// fake folder).
func dedupe(in []Store) []Store {
	var out []Store
	for _, s := range in {
		dup := false
		for i, o := range out {
			if paths.Same(o.Root, s.Root) || paths.Under(o.Root, s.Root) || paths.Under(s.Root, o.Root) {
				if o.Kind == s.Kind && sameApp(o, s) {
					if len(o.Skip) == 0 && len(s.Skip) > 0 {
						out[i] = s
					}
					dup = true
					break
				}
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

func sameApp(a, b Store) bool {
	return strings.EqualFold(firstWord(a.Name), firstWord(b.Name))
}

func firstWord(name string) string {
	f := strings.Fields(strings.TrimPrefix(name, "your "))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// Matches reports whether path is one of the store's files (and not in a
// folder holding baits).
func (s Store) Matches(path string) bool {
	if !paths.Under(path, s.Root) {
		return false
	}
	rel, err := filepath.Rel(s.Root, path)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, sk := range s.Skip {
		if matchRel(sk, rel, true) {
			return false
		}
	}
	for _, f := range s.Files {
		if matchRel(f, rel, false) {
			return true
		}
	}
	return false
}

// matchRel matches a pattern of Store.Files against a path relative to the
// store's root, one folder at a time. prefix: the pattern only has to match
// the start of the path (a folder and everything in it).
func matchRel(pattern, rel string, prefix bool) bool {
	ps, rs := strings.Split(pattern, "/"), strings.Split(rel, "/")
	if len(rs) < len(ps) || (!prefix && len(rs) != len(ps)) {
		return false
	}
	for i, p := range ps {
		a, b := p, rs[i]
		if paths.FoldsCase() {
			a, b = strings.ToLower(a), strings.ToLower(b)
		}
		if ok, err := filepath.Match(a, b); err != nil || !ok {
			return false
		}
	}
	return true
}

// Resolve lists the store's files that exist now, sorted.
func (s Store) Resolve() []string {
	if _, err := os.Stat(s.Root); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range s.Files {
		found, _ := filepath.Glob(filepath.Join(globEscape(s.Root), filepath.FromSlash(f)))
		for _, p := range found {
			if seen[p] || !s.Matches(p) {
				continue
			}
			if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// globEscape keeps the characters glob gives a meaning to as they are, in a
// folder name that has them.
func globEscape(p string) string {
	if !strings.ContainsAny(p, "*?[") {
		return p
	}
	if paths.FoldsCase() && filepath.Separator == '\\' {
		// Windows has no escape character in globs: a "[" is matched by "[[]".
		r := strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]")
		return r.Replace(p)
	}
	r := strings.NewReplacer(`\`, `\\`, "[", `\[`, "*", `\*`, "?", `\?`)
	return r.Replace(p)
}

// StoreFor says which of stores path belongs to.
func StoreFor(stores []Store, path string) (Store, bool) {
	for _, s := range stores {
		if s.Matches(path) {
			return s, true
		}
	}
	return Store{}, false
}
