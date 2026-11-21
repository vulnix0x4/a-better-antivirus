package provenance

// Who vouches for a program on Linux.
//
// There are no code signatures. What tells installed software from something
// that was dropped on the machine is this:
//
//   - a package owns the file: the system's package manager (dpkg, rpm,
//     pacman, apk) lists it as part of something that was installed, or it is
//     inside a snap or a system-wide flatpak;
//   - and nobody but root can have changed it since: the file and every
//     folder on the way to it belong to root and can't be written by anyone
//     else ("root-only").
//
// Both together make Valid, with the package as the Signer. A file that only
// root could have put there but that no package owns (/usr/local/bin, /opt)
// is neither signed nor valid: an administrator installed it, nobody else
// vouches for it. Anything under a folder you can write to is unvouched,
// whatever it is.
//
// It says nothing about what runs inside an interpreter or a shell: for
// those, the rules in package classify look at the script and at what started
// them.

import (
	"bytes"
	"context"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Verify says who made the program (or script) at path.
func Verify(path string) Result {
	if path == "" || !filepath.IsAbs(path) {
		return Result{Error: "no file to check"}
	}
	if strings.HasPrefix(path, "/proc/") {
		return Result{Error: "it runs inside a container or sandbox: its file isn't on this system's package list"}
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Result{Error: "the file is gone"}
	}
	if ok, why := RootOnly(real); !ok {
		return Result{Error: why}
	}
	if name := sandboxed(real); name != "" {
		return Result{Signed: true, Valid: true, Signer: name}
	}
	if pkg := Owner(real); pkg != "" {
		return Result{Signed: true, Valid: true, Signer: pkg}
	}
	return Result{Error: "no package owns it (an administrator put it there)"}
}

// sandboxed names the snap or system-wide flatpak a file is part of. Both
// are read-only images that root installed.
func sandboxed(real string) string {
	for _, root := range []string{"/snap/", "/var/lib/snapd/snap/"} {
		if rest, ok := strings.CutPrefix(real, root); ok {
			if name, _, ok := strings.Cut(rest, "/"); ok && name != "bin" {
				return name + " (snap)"
			}
		}
	}
	for _, root := range []string{"/var/lib/flatpak/app/", "/var/lib/flatpak/runtime/"} {
		if rest, ok := strings.CutPrefix(real, root); ok {
			if name, _, ok := strings.Cut(rest, "/"); ok {
				return name + " (flatpak)"
			}
		}
	}
	return ""
}

// ---- root-only ----

var (
	roMu    sync.Mutex
	roCache = map[string]roEntry{}
)

type roEntry struct {
	ok  bool
	why string
	at  time.Time
}

// RootOnly reports whether only root can have put the file at path there or
// changed it: it, and every folder from / down to it, belongs to root and is
// closed to writing by anyone else. If not, why says which part isn't.
//
// The Nix and Guix stores look root-only but aren't: their daemon adds files
// for any user who asks.
func RootOnly(path string) (ok bool, why string) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return false, "not a full path"
	}
	for _, store := range []string{"/nix/store/", "/gnu/store/"} {
		if strings.HasPrefix(path, store) {
			return false, "any user can add files to " + strings.TrimSuffix(store, "/")
		}
	}
	dir := filepath.Dir(path)
	roMu.Lock()
	e, cached := roCache[dir]
	roMu.Unlock()
	if !cached || time.Since(e.at) > time.Minute {
		e = roEntry{ok: true, at: time.Now()}
		cur := "/"
		for _, part := range append([]string{""}, strings.Split(strings.Trim(dir, "/"), "/")...) {
			cur = filepath.Join(cur, part)
			if w := writable(cur); w != "" {
				e.ok, e.why = false, w
				break
			}
		}
		roMu.Lock()
		if len(roCache) > 4096 {
			roCache = map[string]roEntry{}
		}
		roCache[dir] = e
		roMu.Unlock()
	}
	if !e.ok {
		return false, e.why
	}
	if w := writable(path); w != "" {
		return false, w
	}
	return true, ""
}

// writable says why p could be changed by someone other than root ("" if it
// can't). A missing file is reported too: nothing there to vouch for.
func writable(p string) string {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return p + " doesn't exist"
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		if st.Uid != 0 {
			return p + " is a link that isn't root's"
		}
		return ""
	}
	switch {
	case st.Uid != 0:
		return p + " doesn't belong to root"
	case st.Mode&0o002 != 0:
		return "anyone can write to " + p
	case st.Mode&0o020 != 0 && st.Gid != 0 && groupHasMembers(st.Gid):
		return "a group other than root's can write to " + p
	}
	return ""
}

var (
	grpMu    sync.Mutex
	grpCache = map[uint32]bool{}
	grpAt    time.Time
)

// groupHasMembers reports whether any account is in the group gid. (Debian
// leaves /usr/local writable by the group "staff", which has no members
// unless an administrator adds some.)
func groupHasMembers(gid uint32) bool {
	grpMu.Lock()
	defer grpMu.Unlock()
	if time.Since(grpAt) > time.Minute {
		grpCache, grpAt = map[uint32]bool{}, time.Now()
	}
	if v, ok := grpCache[gid]; ok {
		return v
	}
	want := strconv.FormatUint(uint64(gid), 10)
	has := false
	if b, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":") // name:x:gid:members
			if len(f) >= 4 && f[2] == want && strings.TrimSpace(f[3]) != "" {
				has = true
			}
		}
	} else {
		has = true
	}
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Split(line, ":") // name:x:uid:gid:…
			if len(f) >= 4 && f[3] == want && f[2] != "0" {
				has = true
			}
		}
	}
	grpCache[gid] = has
	return has
}

// ---- which package owns a file ----

var (
	ownMu    sync.Mutex
	ownCache = map[string]string{}
	ownStamp string
)

// Owner returns the installed package that owns the file at path ("" if
// none), asking whichever package manager this system has. Answers are
// remembered until the package database changes.
func Owner(path string) string {
	stamp := dbStamp()
	ownMu.Lock()
	if stamp != ownStamp || len(ownCache) > 8192 {
		ownCache, ownStamp = map[string]string{}, stamp
	}
	pkg, ok := ownCache[path]
	ownMu.Unlock()
	if ok {
		return pkg
	}
	if ix := currentIndex(stamp); ix != nil && !unindexed(path) {
		pkg, ok = ix.find(path)
		if !ok && ix.rpm {
			pkg = rpmOwner(path)
		}
	} else {
		pkg = lookupOwner("/", path)
	}
	ownMu.Lock()
	ownCache[path] = pkg
	ownMu.Unlock()
	return pkg
}

// The answer has to come while a program is stopped inside its open of a
// bait, for it and for everything that started it, and reading every
// package's file list for each of them takes most of a second. So the lists
// are read once, into an index of path hashes (a few megabytes), and again
// whenever the package database changes. Until the index is there, and for
// the kinds of file it leaves out, the lists are searched directly.

type ownerIndex struct {
	stamp string
	names []string
	ents  []ownerEnt // sorted by hash
	rpm   bool       // packages are rpm's here: its database isn't indexed, rpm is asked
}

type ownerEnt struct {
	hash uint64
	pkg  uint32
}

func pathHash(p string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(p))
	return h.Sum64()
}

// unindexed reports whether path is under a folder the index leaves out:
// documentation, translations, icons, headers… the bulk of what packages
// install, and nothing that runs.
func unindexed(path string) bool {
	for _, d := range []string{"/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/", "/usr/share/icons/", "/usr/share/help/",
		"/usr/share/fonts/", "/usr/share/zoneinfo/", "/usr/share/info/", "/usr/share/licenses/", "/usr/share/gtk-doc/", "/usr/share/terminfo/",
		"/usr/share/i18n/", "/usr/share/pixmaps/", "/usr/share/texmf", "/usr/share/texlive/", "/usr/include/", "/usr/src/", "/usr/lib/modules/",
		"/lib/modules/", "/usr/lib/firmware/", "/lib/firmware/", "/boot/"} {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// buildIndex reads the package databases under root.
func buildIndex(root string) *ownerIndex {
	ix := &ownerIndex{}
	pkgIDs := map[string]uint32{}
	add := func(pkg, path string) {
		if path == "" || unindexed(path) {
			return
		}
		id, ok := pkgIDs[pkg]
		if !ok {
			id = uint32(len(ix.names))
			pkgIDs[pkg] = id
			ix.names = append(ix.names, pkg)
		}
		ix.ents = append(ix.ents, ownerEnt{pathHash(path), id})
	}
	lines := func(data []byte, each func(line string)) {
		for len(data) > 0 {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				i = len(data)
			}
			each(string(data[:i]))
			if i == len(data) {
				break
			}
			data = data[i+1:]
		}
	}
	// dpkg: info/<package>[:arch].list, a path per line.
	info := filepath.Join(root, "var/lib/dpkg/info")
	if ents, err := os.ReadDir(info); err == nil {
		for _, e := range ents {
			name, ok := strings.CutSuffix(e.Name(), ".list")
			if !ok {
				continue
			}
			pkg, _, _ := strings.Cut(name, ":")
			if data, err := os.ReadFile(filepath.Join(info, e.Name())); err == nil {
				lines(data, func(l string) { add(pkg, l) })
			}
		}
	}
	// pacman: local/<name-version-release>/files, paths without the leading slash.
	local := filepath.Join(root, "var/lib/pacman/local")
	if ents, err := os.ReadDir(local); err == nil {
		for _, e := range ents {
			data, err := os.ReadFile(filepath.Join(local, e.Name(), "files"))
			if err != nil {
				continue
			}
			pkg := e.Name()
			for i := 0; i < 2; i++ {
				if j := strings.LastIndexByte(pkg, '-'); j > 0 {
					pkg = pkg[:j]
				}
			}
			in := false
			lines(data, func(l string) {
				switch {
				case strings.HasPrefix(l, "%"):
					in = l == "%FILES%"
				case in && l != "" && !strings.HasSuffix(l, "/"):
					add(pkg, "/"+l)
				}
			})
		}
	}
	// apk: one file, a block per package.
	if data, err := os.ReadFile(filepath.Join(root, "lib/apk/db/installed")); err == nil {
		pkg, dir := "", ""
		lines(data, func(l string) {
			switch {
			case strings.HasPrefix(l, "P:"):
				pkg = l[2:]
			case strings.HasPrefix(l, "F:"):
				dir = l[2:]
			case strings.HasPrefix(l, "R:"):
				add(pkg, "/"+dir+"/"+l[2:])
			}
		})
	}
	sort.Slice(ix.ents, func(i, j int) bool { return ix.ents[i].hash < ix.ents[j].hash })
	// rpm is only asked where it is the system's package manager. (Debian and
	// Ubuntu machines often have the rpm tool and an empty database of its
	// own, and asking it costs a process per question.)
	if len(ix.ents) == 0 {
		for _, db := range []string{"var/lib/rpm", "usr/lib/sysimage/rpm"} {
			if ents, err := os.ReadDir(filepath.Join(root, db)); err == nil && len(ents) > 0 {
				ix.rpm = true
			}
		}
	}
	return ix
}

// find looks path up under each name it may be listed by.
func (ix *ownerIndex) find(path string) (string, bool) {
	for _, n := range aliases(path) {
		h := pathHash(n)
		i := sort.Search(len(ix.ents), func(i int) bool { return ix.ents[i].hash >= h })
		if i < len(ix.ents) && ix.ents[i].hash == h {
			return ix.names[ix.ents[i].pkg], true
		}
	}
	return "", false
}

var (
	ixMu       sync.Mutex
	ix         *ownerIndex
	ixBuilding bool
)

// currentIndex returns the index if it's up to date, and otherwise starts
// building one in the background (nil for now).
func currentIndex(stamp string) *ownerIndex {
	ixMu.Lock()
	defer ixMu.Unlock()
	if ix != nil && ix.stamp == stamp {
		return ix
	}
	if !ixBuilding {
		ixBuilding = true
		go func() {
			built := buildIndex("/")
			built.stamp = stamp
			ixMu.Lock()
			ix, ixBuilding = built, false
			ixMu.Unlock()
		}()
	}
	return nil
}

// Warm gets the index ready ahead of the first question (the service calls
// it when it starts).
func Warm() { currentIndex(dbStamp()) }

// dbStamp changes whenever packages are installed or removed.
func dbStamp() string {
	var b strings.Builder
	for _, p := range []string{"/var/lib/dpkg/status", "/var/lib/pacman/local", "/lib/apk/db/installed",
		"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages.db"} {
		if fi, err := os.Stat(p); err == nil {
			b.WriteString(strconv.FormatInt(fi.ModTime().UnixNano(), 36) + ";")
		}
	}
	return b.String()
}

// lookupOwner asks each package database found under root (a parameter so
// tests can point it at a made-up one).
func lookupOwner(root, path string) string {
	names := aliases(path)
	if pkg := dpkgOwner(filepath.Join(root, "var/lib/dpkg/info"), names); pkg != "" {
		return pkg
	}
	if pkg := pacmanOwner(filepath.Join(root, "var/lib/pacman/local"), names); pkg != "" {
		return pkg
	}
	if pkg := apkOwner(filepath.Join(root, "lib/apk/db/installed"), names); pkg != "" {
		return pkg
	}
	// rpm only where it's the system's package manager (see buildIndex).
	if root != "/" {
		return ""
	}
	for _, db := range []string{"/var/lib/dpkg/info", "/var/lib/pacman/local", "/lib/apk/db/installed"} {
		if _, err := os.Stat(db); err == nil {
			return ""
		}
	}
	return rpmOwner(path)
}

// aliases are the names a file may be listed under. Systems that merged /bin
// into /usr/bin still have packages that list their files the old way.
func aliases(path string) []string {
	out := []string{path}
	for _, d := range []string{"bin", "sbin", "lib", "lib32", "lib64", "libx32"} {
		if rest, ok := strings.CutPrefix(path, "/usr/"+d+"/"); ok {
			out = append(out, "/"+d+"/"+rest)
		} else if rest, ok := strings.CutPrefix(path, "/"+d+"/"); ok {
			out = append(out, "/usr/"+d+"/"+rest)
		}
	}
	return out
}

// hasLine reports whether data (lines of text) has a line that is exactly one
// of the given ones.
func hasLine(data []byte, lines [][]byte) bool {
	for _, l := range lines {
		for from := 0; ; {
			i := bytes.Index(data[from:], l)
			if i < 0 {
				break
			}
			i += from
			end := i + len(l)
			if (i == 0 || data[i-1] == '\n') && (end == len(data) || data[end] == '\n') {
				return true
			}
			from = i + 1
		}
	}
	return false
}

// dpkgOwner looks the file up in dpkg's lists: one file per package, with a
// path on each line.
func dpkgOwner(infoDir string, names []string) string {
	ents, err := os.ReadDir(infoDir)
	if err != nil {
		return ""
	}
	var want [][]byte
	for _, n := range names {
		want = append(want, []byte(n))
	}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".list")
		if !ok {
			continue
		}
		data, err := os.ReadFile(filepath.Join(infoDir, e.Name()))
		if err != nil || !hasLine(data, want) {
			continue
		}
		pkg, _, _ := strings.Cut(name, ":") // libc6:amd64
		return pkg
	}
	return ""
}

// pacmanOwner looks the file up in pacman's database: a folder per package
// with a "files" list, paths without the leading slash.
func pacmanOwner(localDir string, names []string) string {
	ents, err := os.ReadDir(localDir)
	if err != nil {
		return ""
	}
	var want [][]byte
	for _, n := range names {
		want = append(want, []byte(strings.TrimPrefix(n, "/")))
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(localDir, e.Name(), "files"))
		if err != nil || !hasLine(data, want) {
			continue
		}
		// name-version-release
		name := e.Name()
		for i := 0; i < 2; i++ {
			if j := strings.LastIndexByte(name, '-'); j > 0 {
				name = name[:j]
			}
		}
		return name
	}
	return ""
}

// apkOwner looks the file up in Alpine's database: one text file, a block per
// package with P:name, F:folder and R:file lines.
func apkOwner(dbFile string, names []string) string {
	data, err := os.ReadFile(dbFile)
	if err != nil {
		return ""
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.TrimPrefix(n, "/")] = true
	}
	pkg, dir := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "P:"):
			pkg = line[2:]
		case strings.HasPrefix(line, "F:"):
			dir = line[2:]
		case strings.HasPrefix(line, "R:"):
			if want[dir+"/"+line[2:]] {
				return pkg
			}
		}
	}
	return ""
}

// rpmOwner asks rpm, whose database isn't a format ABA reads itself.
func rpmOwner(path string) string {
	rpm := ""
	for _, p := range []string{"/usr/bin/rpm", "/bin/rpm"} {
		if _, err := os.Stat(p); err == nil {
			rpm = p
			break
		}
	}
	if rpm == "" {
		return ""
	}
	have := false
	for _, db := range []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm"} {
		if ents, err := os.ReadDir(db); err == nil && len(ents) > 0 {
			have = true
		}
	}
	if !have {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, rpm, "-qf", "--qf", "%{NAME}\n", path)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if name == "" || strings.Contains(name, " ") {
		return ""
	}
	return name
}
