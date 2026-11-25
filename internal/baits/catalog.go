// Package baits defines every bait ABA can plant (plain files and fake
// application data that stealers target), decides which ones fit this PC, and
// creates, checks, retires and removes them.
//
// What a bait is and how it's planted, checked and retired is the same on
// every operating system. Three things aren't, and each is in a *_<os>.go
// file: the Catalog (where each app keeps its data and installs to), how a
// bait file is made to blend in (blend), and the tripwire that has to be put
// on the file itself, if the OS needs one.
package baits

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Kind of bait.
const (
	KindFile   = "file"   // a tempting document in your folders
	KindDecoy  = "decoy"  // fake data for an app you don't use
	KindCanary = "canary" // credentials that phone home when used
)

// Spec describes one bait in the catalog.
type Spec struct {
	ID          string
	Name        string
	Category    string
	Kind        string
	Description string
	Default     bool   // preselected when available
	Caveat      string // shown for opt-in baits
	// Root is the app's data folder. If it already exists before install, the
	// real app is (or was) installed and this decoy is unavailable.
	Root func(u config.UserInfo) string
	// Markers are globs whose existence means the genuine app is installed.
	Markers   func(u config.UserInfo) []string
	OwnerExes []string // genuine executables (lowercase)
	Signer    string   // substring of the genuine app's signer
	// SharedSDK: the file sits where a vendor SDK's default credential lookup
	// reads on startup, so many legitimate signed apps touch it. Signed,
	// non-script readers are logged but not alerted; everything else trips it.
	SharedSDK bool
	// RequiresAny: this bait lives inside one of these (e.g. MetaMask inside a fake browser).
	RequiresAny []string
	Files       func(u config.UserInfo) []FileSpec
	// Inside and Host make this a bait inside a real app (see embeddedProfile):
	// Inside is the app's data folder it's planted in, Host the app's
	// executable in the places it installs to. It's only available when the
	// app is there, the opposite of a decoy.
	Inside func(u config.UserInfo) string
	Host   func(u config.UserInfo) []string
	// Profiles is the file in Inside where the app lists the profiles it
	// uses: "Local State" for the Chromium family (when empty), "profiles.ini"
	// for Firefox. It existing shows the app has been used.
	Profiles string
	// ProfileDir is the folder under Inside that Firefox keeps its profile
	// folders in: "Profiles" on Windows and macOS, Inside itself on Linux.
	ProfileDir string
	// Synced (optional) says, in one sentence, that the folder the bait is
	// planted in is kept in sync with a cloud (on macOS: Desktop and
	// Documents in iCloud Drive), so the decoy will be uploaded and show up
	// on the person's other devices. "" when it isn't. Setup asks before
	// planting such baits (yes by default).
	Synced func(u config.UserInfo) string
	// Adopt: a file that's already at the bait's path becomes the bait, as it
	// is. Only for a bait you added yourself (`aba bait add <path>`): you
	// chose that file. A catalog bait never takes over a file (see Settle).
	Adopt bool
	// Since is the config version that introduced this bait, when it's newer
	// than the catalog's first version: setup then offers it to installs
	// configured before it existed.
	Since int
}

// FileSpec is one file of a bait.
type FileSpec struct {
	Path  string
	Audit bool // put the read/delete audit rule on it
	Text  bool // human-readable (shown by `bait show`)
	Gen   func(g *Gen) []byte
	// Alt is where the file's name came from, when it was picked from a pool:
	// what Settle needs to give it another name if a file of yours has this
	// one already.
	Alt *Alt
}

// Alt is the pool a bait file's name was picked from, and what the pick is
// kept under in config.UserInfo.Names when it isn't the usual one.
type Alt struct {
	What string
	Pool []string
}

func j(parts ...string) string { return filepath.Join(parts...) }

// ---- per-install variation ----
//
// ABA is open source, so a stealer can know this catalog by heart. If every
// install used the same file names, skipping "wallet recovery phrase.txt" by
// name would be a one-line bypass. So each install picks its own names from
// pools of what file grabbers look for (pass, seed, wallet, backup, 2fa…):
// to skip the baits a stealer would have to skip everything it came for.
//
// The choice is derived from u.Variant, a random value fixed at install time.
// Installs from before this existed have no Variant and keep their old names.

func variantN(u config.UserInfo, what string, n int) int {
	h := sha256.Sum256([]byte(u.Variant + "|" + what))
	return int(binary.LittleEndian.Uint32(h[:4]) % uint32(n))
}

// vary picks one of pool for this install (the first one without a Variant).
func vary(u config.UserInfo, what string, pool ...string) string {
	if n := u.Names[what]; n != "" {
		return n // the usual pick was a file of yours: see Settle
	}
	if u.Variant == "" {
		return pool[0]
	}
	return pool[variantN(u, what, len(pool))]
}

// varyChars is a per-install string of n characters from alphabet (def
// without a Variant).
func varyChars(u config.UserInfo, what, def string, n int, alphabet string) string {
	if u.Variant == "" {
		return def
	}
	h := sha256.Sum256([]byte(u.Variant + "|" + what))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[int(h[i%len(h)]+byte(i))%len(alphabet)]
	}
	return string(b)
}

// varyFile is vary for the name of a bait's file. It also returns what Settle
// needs to pick another name of the pool.
func varyFile(u config.UserInfo, what string, pool ...string) (string, *Alt) {
	return vary(u, what, pool...), &Alt{What: what, Pool: pool}
}

func passwordsName(u config.UserInfo, where string) (string, *Alt) {
	return varyFile(u, "passwords-"+where, "passwords.txt", "my passwords.txt", "Passwords.txt", "password list.txt",
		"logins and passwords.txt", "pass.txt", "accounts and passwords.txt", "passwords backup.txt")
}

// Settle keeps a catalog bait off files that are already there. A
// Passwords.kdbx of your own is not a bait, and ABA must never take it for
// one: it would watch your file, alert on your own programs opening it, and
// put it back if you deleted it.
//
// Where this install's name for one of s's files is taken, the next free name
// of its pool is used instead and kept in u.Names. ours are the files ABA
// planted itself (paths.Key of each): those aren't in the way. Settle returns
// the files that still are (no pool to pick from, or every name of it taken):
// s can't be planted while they're there.
//
// It's for a bait that isn't planted yet. Baits inside a real app's data are
// placed by FreeProfile, and a bait you added yourself is a file you chose.
func Settle(s Spec, u *config.UserInfo, ours map[string]bool) (inTheWay []string) {
	if s.Files == nil || s.Adopt || s.Inside != nil {
		return nil
	}
	for _, f := range s.Files(*u) {
		if !taken(f.Path, ours) {
			continue
		}
		free := ""
		if f.Alt != nil {
			dir, at := filepath.Dir(f.Path), 0
			for i, name := range f.Alt.Pool {
				if name == filepath.Base(f.Path) {
					at = i
				}
			}
			for i := 1; i < len(f.Alt.Pool) && free == ""; i++ {
				if name := f.Alt.Pool[(at+i)%len(f.Alt.Pool)]; !taken(j(dir, name), ours) {
					free = name
				}
			}
		}
		if free == "" {
			inTheWay = append(inTheWay, f.Path)
			continue
		}
		// A copy: u may share its map with the config it was taken from.
		names := map[string]string{}
		for k, v := range u.Names {
			names[k] = v
		}
		names[f.Alt.What] = free
		u.Names = names
	}
	return inTheWay
}

// taken reports whether something that isn't ABA's is at path already.
func taken(path string, ours map[string]bool) bool {
	if ours[paths.Key(path)] {
		return false
	}
	fi, err := os.Lstat(path)
	if err != nil {
		// Not there. Anything else (a folder ABA can't look into) counts as
		// taken: better one bait fewer than a bait on top of something.
		return !errors.Is(err, os.ErrNotExist)
	}
	return !legacyBait(path, fi)
}

// legacyBait reports whether the file at path was planted by the original
// PowerShell honeypot script: those are taken over and cleaned up as ABA's.
func legacyBait(path string, fi os.FileInfo) bool {
	if !fi.Mode().IsRegular() || fi.Size() > 64<<10 {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && hasLegacyMarker(b)
}

// ldbName is a LevelDB file name the way real ones look: a six-digit sequence
// number that depends on how long the app has been used.
func ldbName(u config.UserInfo, what, def, ext string) string {
	if u.Variant == "" {
		return def
	}
	return "0000" + varyChars(u, what, "", 2, "0123456789") + ext
}

const metamaskID = "nkbihfbeogaeaoehlefnkodbefgpgknn"

// decoyBrowsers can host fake extension data, in order of preference.
var decoyBrowsers = []string{"vivaldi", "yandex", "brave"}

// ChooseHost picks the decoy browser that will host dependent baits (MetaMask)
// from the selected IDs. Returns "" if none is selected.
func ChooseHost(selected map[string]bool) string {
	for _, b := range decoyBrowsers {
		if selected[b] {
			return b
		}
	}
	return ""
}

func chromiumFiles(userData string, passwords string) []FileSpec {
	if passwords == "" {
		passwords = "Login Data"
	}
	return []FileSpec{
		{Path: j(userData, "Local State"), Audit: true, Gen: genLocalState},
		{Path: j(userData, "Default", passwords), Audit: true, Gen: genLoginData},
		{Path: j(userData, "Default", "Network", "Cookies"), Audit: true, Gen: genCookies},
		{Path: j(userData, "Default", "Web Data"), Audit: true, Gen: genWebData},
		{Path: j(userData, "Default", "Preferences"), Gen: genPreferences},
	}
}

// ---- baits inside real browsers ----
//
// A decoy is fake data for an app you don't have. A stealer that knows ABA
// can turn that around: check that the app is really installed before
// touching its data, and no decoy is ever opened. So for the browsers you do
// have, ABA plants a fake extra *profile* inside the real one's data: a
// "Profile 23" folder next to "Default". Stealers take every profile folder
// they find (that's how they get people's work and second accounts), and here
// "is the browser installed?" says yes.
//
// The browser itself only opens the profiles listed in its "Local State"
// file, so it never touches this one. If it ever does (you created profiles
// until it reached that number, and it adopted the folder), ABA retires the
// bait like a decoy whose app got installed.

type localState struct {
	Profile struct {
		InfoCache map[string]json.RawMessage `json:"info_cache"`
		Created   int                        `json:"profiles_created"`
	} `json:"profile"`
}

func readLocalState(userData string) (ls localState, ok bool) {
	b, err := os.ReadFile(j(userData, "Local State"))
	if err != nil {
		return ls, false
	}
	return ls, json.Unmarshal(b, &ls) == nil
}

// ProfileFolder is the folder name of an embedded profile bait.
func ProfileFolder(u config.UserInfo, id string) string {
	if f := u.Embedded[id]; f != "" {
		return f
	}
	return fmt.Sprintf("Profile %d", 21+variantN(u, id, 18))
}

// FreeProfile picks a profile folder name the browser isn't using and won't
// get to soon: well past the number of profiles it has ever created.
func FreeProfile(s Spec, u config.UserInfo) string {
	ud := s.Inside(u)
	if s.profilesFile() == firefoxIndex {
		// A Firefox profile folder: eight random letters and digits, then what
		// Firefox names a second default profile.
		used := firefoxProfiles(ud)
		for try := 0; try < 60; try++ {
			name := randAlnum(8, "abcdefghijklmnopqrstuvwxyz0123456789") + ".default-release-1"
			if _, err := os.Stat(j(ud, s.ProfileDir, name)); err != nil && !used[name] {
				return name
			}
		}
	}
	ls, _ := readLocalState(ud)
	base := ls.Profile.Created + 8
	if base < 12 {
		base = 12
	}
	for try := 0; try < 60; try++ {
		name := fmt.Sprintf("Profile %d", base+rint(20))
		if _, err := os.Stat(j(ud, name)); err == nil {
			continue
		}
		if _, used := ls.Profile.InfoCache[name]; !used {
			return name
		}
	}
	return fmt.Sprintf("Profile %d", base+20+rint(900))
}

// profileMargin is how close a Chromium browser's count of profiles ever
// created may come to the fake profile's number before the fake is moved
// further out (see Crowded). FreeProfile starts it at least 8 past.
const profileMargin = 4

// Crowded reports whether the real browser is about to name a new profile
// after an embedded bait's folder. A Chromium browser names the profile you
// add "Profile N", N from the count of profiles it has ever created
// (profile.profiles_created in Local State, absent until the first one: 1),
// skipping the names it has registered but not folders that merely exist: it
// would wipe the fake profile and take its folder. Abandoned profiles count
// too, so the count only grows. Firefox names profiles at random: never.
func Crowded(s Spec, u config.UserInfo) bool {
	if s.Inside == nil || s.profilesFile() == firefoxIndex {
		return false
	}
	var n int
	if _, err := fmt.Sscanf(ProfileFolder(u, s.ID), "Profile %d", &n); err != nil {
		return false
	}
	ls, ok := readLocalState(s.Inside(u))
	if !ok {
		return false
	}
	created := ls.Profile.Created
	if created < 1 {
		created = 1
	}
	return created+profileMargin >= n
}

// TakenOver reports whether the real browser has made an embedded bait's
// folder a profile of its own on disk, whether or not it has written that
// down in its list of profiles yet (it does so lazily, seconds later): the
// folder now holds at least two things the fake profile never had (a real
// profile's settings, caches, sessions…). A stealer only reads the fake; a
// database it opens may leave a journal beside it, which doesn't count.
func TakenOver(s Spec, u config.UserInfo) bool {
	if s.Inside == nil {
		return false
	}
	files := s.Files(u)
	if len(files) == 0 {
		return false
	}
	dir := filepath.Dir(files[0].Path)
	ours := map[string]bool{}
	for _, f := range files {
		rel, err := filepath.Rel(dir, f.Path)
		if err != nil {
			continue
		}
		ours[strings.ToLower(strings.SplitN(filepath.ToSlash(rel), "/", 2)[0])] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	foreign := 0
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if ours[n] || strings.HasSuffix(n, "-journal") || strings.HasSuffix(n, "-wal") || strings.HasSuffix(n, "-shm") {
			continue
		}
		foreign++
	}
	return foreign >= 2
}

// Adopted reports whether the real browser has taken an embedded bait's
// folder as one of its own profiles (it's listed in Local State).
func Adopted(s Spec, u config.UserInfo) bool {
	if s.Inside == nil {
		return false
	}
	if s.profilesFile() == firefoxIndex {
		return firefoxProfiles(s.Inside(u))[firefoxFolder(u, s.ID)]
	}
	ls, ok := readLocalState(s.Inside(u))
	if !ok {
		return false
	}
	_, used := ls.Profile.InfoCache[ProfileFolder(u, s.ID)]
	return used
}

const firefoxIndex = "profiles.ini"

func (s Spec) profilesFile() string {
	if s.Profiles != "" {
		return s.Profiles
	}
	return "Local State"
}

// firefoxProfiles lists the profile folders a Firefox data folder's
// profiles.ini names: the only ones Firefox opens.
func firefoxProfiles(root string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(j(root, firefoxIndex))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Path="); ok {
			out[filepath.Base(filepath.FromSlash(v))] = true
		}
	}
	return out
}

// firefoxFolder is the folder name of an embedded Firefox profile bait.
func firefoxFolder(u config.UserInfo, id string) string {
	if f := u.Embedded[id]; f != "" {
		return f
	}
	return varyChars(u, id, "w7d2kq9p", 8, "abcdefghijklmnopqrstuvwxyz0123456789") + ".default-release-1"
}

// embeddedFirefox is a fake profile inside a real Firefox: a folder next to
// the real profiles that profiles.ini doesn't list, so Firefox never opens
// it, and stealers that take every profile folder do. root holds
// profiles.ini, sub (under root) the profile folders; since is the config
// version that first offered it (see Spec.Since).
func embeddedFirefox(id, browser, signer string, since int, root func(u config.UserInfo) string, sub string, hosts func(u config.UserInfo) []string) Spec {
	return Spec{
		ID: id, Name: "extra profile inside your " + browser, Category: "Browsers", Kind: KindDecoy, Default: true, Since: since,
		Description: "A fake profile next to your real ones. Stealers take every profile; " + browser + " never opens this one.",
		OwnerExes:   []string{"firefox", "firefox-bin", "firefox-esr", "firefox.exe"}, Signer: signer,
		Inside: root, Host: hosts, Profiles: firefoxIndex, ProfileDir: sub,
		Files: func(u config.UserInfo) []FileSpec {
			d := j(root(u), sub, firefoxFolder(u, id))
			return []FileSpec{
				{Path: j(d, "logins.json"), Audit: true, Gen: genFirefoxLogins},
				{Path: j(d, "key4.db"), Audit: true, Gen: genKey4},
				{Path: j(d, "cookies.sqlite"), Audit: true, Gen: genMozCookies},
				{Path: j(d, "times.json"), Gen: func(*Gen) []byte {
					return []byte(fmt.Sprintf(`{"created":%d,"firstUse":null}`, past(400).UnixMilli()))
				}},
			}
		},
	}
}

func embeddedProfile(id, browser, exe, signer string, userData func(u config.UserInfo) string, appDirs func(u config.UserInfo) []string) Spec {
	return Spec{
		ID: id, Name: "extra profile inside your " + browser, Category: "Browsers", Kind: KindDecoy, Default: true, Since: 3,
		Description: "A fake profile next to your real ones. Stealers take every profile; " + browser + " never opens this one.",
		OwnerExes:   []string{exe}, Signer: signer,
		Inside: userData,
		Host: func(u config.UserInfo) []string {
			var out []string
			for _, d := range appDirs(u) {
				out = append(out, j(d, exe))
			}
			return out
		},
		Files: func(u config.UserInfo) []FileSpec {
			d := j(userData(u), ProfileFolder(u, id))
			return []FileSpec{
				{Path: j(d, "Login Data"), Audit: true, Gen: genLoginData},
				{Path: j(d, "Network", "Cookies"), Audit: true, Gen: genCookies},
				{Path: j(d, "Web Data"), Audit: true, Gen: genWebData},
				{Path: j(d, "Preferences"), Gen: genPreferences},
			}
		},
	}
}

// ByID finds a spec.
func ByID(id string) (Spec, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

// Availability of a bait on this PC.
type Availability struct {
	Spec      Spec
	Available bool
	Reason    string // why not
}

// Plan reports which catalog baits fit this user. alreadyOurs lists bait IDs
// ABA already created (their Root existing is expected, not a real app).
func Plan(u config.UserInfo, alreadyOurs map[string]bool) []Availability {
	var out []Availability
	avail := map[string]bool{}
	for _, s := range Catalog {
		a := Availability{Spec: s, Available: true}
		if s.Markers != nil {
			// A marker that isn't the genuine app doesn't take away a bait that's
			// already planted: planting a fake one is how you'd try to get rid of it.
			if m, genuine := Installed(s, u); m != "" && (genuine || !alreadyOurs[s.ID]) {
				a.Available, a.Reason = false, "you have it installed ("+m+")"
			}
		}
		if s.Inside != nil {
			// Needs the real browser: its program, and data it has actually used.
			_, errData := os.Stat(j(s.Inside(u), s.profilesFile()))
			if firstExisting(s.Host(u)) == "" || errData != nil {
				a.Available, a.Reason = false, "you don't use it"
			}
		}
		if a.Available && s.Root != nil && !alreadyOurs[s.ID] {
			if _, err := os.Stat(s.Root(u)); err == nil {
				a.Available, a.Reason = false, "its data folder already exists (you use or used it)"
			}
		}
		if a.Available && s.Kind == KindFile && !alreadyOurs[s.ID] {
			for _, f := range s.Files(u) {
				if _, err := os.Stat(filepath.Dir(f.Path)); err != nil {
					a.Available, a.Reason = false, "folder "+filepath.Dir(f.Path)+" doesn't exist"
				}
			}
		}
		if a.Available && !alreadyOurs[s.ID] {
			uu := u // Settle only changes its own copy
			if in := Settle(s, &uu, nil); len(in) > 0 {
				a.Available, a.Reason = false, "you already have a file there with that name ("+in[0]+")"
			}
		}
		if a.Available && len(s.RequiresAny) > 0 {
			ok := false
			for _, r := range s.RequiresAny {
				ok = ok || avail[r]
			}
			if !ok {
				a.Available, a.Reason = false, "needs one of the fake browsers ("+strings.Join(s.RequiresAny, ", ")+"), and you use all of them"
			}
		}
		avail[s.ID] = a.Available
		out = append(out, a)
	}
	return out
}

// InstalledMarker returns the first marker that exists (the real app may be installed).
func InstalledMarker(s Spec, u config.UserInfo) string {
	if s.Markers == nil {
		return ""
	}
	return firstExisting(s.Markers(u))
}

// Genuine reports whether the file at path really is the app's executable:
// validly signed by its publisher. A variable so tests can stand in for it.
var Genuine = func(path, signer string) bool {
	r := provenance.Verify(path)
	return r.Valid && (signer == "" || strings.Contains(strings.ToLower(r.Signer), strings.ToLower(signer)))
}

// Installed looks for the app a decoy imitates. It returns the marker found
// and whether it's genuine.
//
// Most of these apps install into your own profile, where no admin rights are
// needed, so anything running as you can create "Discord\Update.exe" too.
// An empty or unsigned file there isn't the app: it's what a stealer would
// plant to make ABA retire its Discord decoy by itself. Only a file signed by
// the app's publisher counts, or one in Program Files (which takes admin
// rights to write to: adminOnly, per operating system).
func Installed(s Spec, u config.UserInfo) (marker string, genuine bool) {
	if s.Markers == nil {
		return "", false
	}
	for _, g := range s.Markers(u) {
		var found []string
		if strings.ContainsAny(g, "*?[") {
			found, _ = filepath.Glob(g)
		} else if _, err := os.Stat(g); err == nil {
			found = []string{g}
		}
		for _, m := range found {
			if marker == "" {
				marker = m
			}
			if adminOnly(m) || Genuine(m, s.Signer) {
				return m, true
			}
		}
	}
	return marker, false
}

// OwnerDirs are the folders the genuine app installs into (where its markers
// are): the only places "the real app" can be running from.
func OwnerDirs(s Spec, u config.UserInfo) []string {
	var markers []string
	if s.Markers != nil {
		markers = s.Markers(u)
	}
	if s.Host != nil {
		markers = append(markers, s.Host(u)...)
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range markers {
		d := filepath.Dir(m)
		if strings.ContainsAny(d, "*?[") || seen[strings.ToLower(d)] {
			continue
		}
		seen[strings.ToLower(d)] = true
		out = append(out, d)
	}
	return out
}

func firefoxProfile(u config.UserInfo) string {
	return varyChars(u, "firefox", "q8m3kx2v", 8, "abcdefghijklmnopqrstuvwxyz0123456789") + ".default-release"
}

func firstExisting(globs []string) string {
	for _, g := range globs {
		if strings.ContainsAny(g, "*?[") {
			if m, _ := filepath.Glob(g); len(m) > 0 {
				return m[0]
			}
			continue
		}
		if _, err := os.Stat(g); err == nil {
			return g
		}
	}
	return ""
}

// Categories returns category names in catalog order.
func Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Catalog {
		if !seen[s.Category] {
			seen[s.Category] = true
			out = append(out, s.Category)
		}
	}
	return out
}

// DependentsOf returns IDs that require id.
func DependentsOf(id string) []string {
	var out []string
	for _, s := range Catalog {
		for _, r := range s.RequiresAny {
			if r == id {
				out = append(out, s.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CustomSpec builds a spec for a user-chosen file (adopted if it exists,
// otherwise filled with a fake passwords list).
func CustomSpec(id, path string) Spec {
	return Spec{
		ID: id, Name: filepath.Base(path) + " (custom)", Category: "Custom", Kind: KindFile, Adopt: true,
		Files: func(config.UserInfo) []FileSpec {
			return []FileSpec{{Path: path, Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	}
}

// SpecFor resolves a configured bait (catalog or custom).
func SpecFor(b config.BaitConfig) (Spec, bool) {
	if b.Path != "" {
		return CustomSpec(b.ID, b.Path), true
	}
	return ByID(b.ID)
}

// SpecByID resolves an ID using the config's custom baits too.
func SpecByID(cfg *config.Config, id string) (Spec, bool) {
	for _, b := range cfg.Baits {
		if b.ID == id {
			return SpecFor(b)
		}
	}
	return ByID(id)
}

// Moved reports whether a planted bait's files are no longer where its spec
// puts them for u (the install was given new bait names).
func Moved(bs *config.BaitState, s Spec, u config.UserInfo) bool {
	want := s.Files(u)
	if len(want) != len(bs.Files) {
		return true
	}
	have := map[string]bool{}
	for _, f := range bs.Files {
		have[paths.Key(f.Path)] = true
	}
	for _, f := range want {
		if !have[paths.Key(f.Path)] {
			return true
		}
	}
	return false
}

// SyncNote says whether any of the chosen baits (ids) would be planted in a
// folder that syncs to a cloud: the sentence that explains it, and which
// baits those are.
func SyncNote(plan []Availability, u config.UserInfo, ids []string) (note string, synced []string) {
	chosen := map[string]bool{}
	for _, id := range ids {
		chosen[id] = true
	}
	for _, a := range plan {
		if !a.Available || !chosen[a.Spec.ID] || a.Spec.Synced == nil {
			continue
		}
		if n := a.Spec.Synced(u); n != "" {
			note = n
			synced = append(synced, a.Spec.ID)
		}
	}
	return note, synced
}
