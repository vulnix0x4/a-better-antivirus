package autopsy

// Files that appeared while the program ran, where stealers stage what they
// collect: a folder in Temp, an archive in the program's own folder. A file
// that appeared there isn't proof the program made it (anything else
// running could have); one it holds open is.

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// Limits on the search.
const (
	maxVisit   = 30000 // entries looked at in all
	maxPerDir  = 3000  // a folder with more is looked at only that far
	maxStaged  = 200
	maxStagedB = 4 << 30
)

// findStaged lists regular files under dirs that appeared at or after
// since, skipping skip (the baits) and ABA's own evidence folder. where is
// the list of folders actually looked through. Files own says are the
// program's own (its unpacked code, see ownCode) aren't listed, only counted
// by folder in mine, so a program that unpacks thousands of files can't push
// what it collected off the list.
func findStaged(dirs []Dir, since time.Time, skip map[string]bool, evidence string, own func(p string) bool) (out []*alerts.Staged, where []string, mine map[string]*alerts.Unpacked) {
	mine = map[string]*alerts.Unpacked{}
	visited := 0
	done := map[string]bool{}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if visited >= maxVisit || done[paths.Key(dir)] {
			return
		}
		done[paths.Key(dir)] = true
		if evidence != "" && (paths.Same(dir, evidence) || paths.Under(dir, evidence)) {
			return
		}
		if paths.Same(dir, paths.DataDir()) || paths.Under(dir, paths.DataDir()) {
			return
		}
		f, err := os.Open(dir)
		if err != nil {
			return
		}
		entries, _ := f.ReadDir(maxPerDir)
		f.Close()
		for _, e := range entries {
			visited++
			if visited >= maxVisit {
				return
			}
			p := filepath.Join(dir, e.Name())
			if e.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if e.IsDir() {
				if depth > 0 {
					walk(p, depth-1)
				}
				continue
			}
			if !e.Type().IsRegular() || skip[p] {
				continue
			}
			fi, err := e.Info()
			if err != nil || fi.Size() > maxStagedB {
				continue
			}
			at := appeared(fi)
			if at.Before(since) {
				continue
			}
			if own != nil && own(p) {
				u := mine[dir]
				if u == nil {
					u = &alerts.Unpacked{Dir: dir}
					mine[dir] = u
				}
				u.Files++
				u.Size += fi.Size()
				continue
			}
			if len(out) < maxStaged {
				out = append(out, &alerts.Staged{Path: p, Size: fi.Size(), Appeared: at})
			}
		}
	}
	for _, d := range dirs {
		if d.Path == "" {
			continue
		}
		if _, err := os.Stat(d.Path); err != nil {
			continue
		}
		if !done[paths.Key(d.Path)] {
			where = append(where, d.Path)
		}
		walk(d.Path, d.Depth)
	}
	sortStaged(out)
	return out, where, mine
}

// codeExts are the kinds of file a program runs code from: what a
// self-unpacking program (PyInstaller, Electron, a .NET single file…)
// unpacks next to the libraries it loads.
var codeExts = map[string]bool{".dll": true, ".pyd": true, ".pyc": true, ".exe": true, ".so": true, ".dylib": true,
	".node": true, ".jar": true, ".manifest": true, ".mui": true}

// ownCode says whether p is the program's own code: a file it runs code from
// (code, its loaded program and libraries), or a program file (by its kind)
// in a folder it runs code from (dirs). Never a file of data: what it
// collected is listed even when it put it beside its own libraries.
func ownCode(p string, code, dirs map[string]bool) bool {
	if code[paths.Key(p)] {
		return true
	}
	return dirs[paths.Key(filepath.Dir(p))] && codeExts[strings.ToLower(filepath.Ext(p))]
}

// homeDirs are the staging places every system has: the downloads,
// desktop and documents (stealers drop what they collect beside
// themselves), and the top of the home and app data folders (where they
// make a folder of their own).
func homeDirs(c *Case) []Dir {
	u := c.User
	var out []Dir
	for _, d := range []Dir{{u.Downloads, 1}, {u.Desktop, 1}, {u.Documents, 1}, {u.Profile, 1}, {u.LocalAppData, 1}, {u.RoamingAppData, 1}} {
		if d.Path != "" && !strings.Contains(strings.ToLower(d.Path), "onedrive") {
			out = append(out, d)
		}
	}
	return out
}

// allCode: every entry of an archive is a program file (and none is a bait
// or a copy of a real file).
func allCode(entries []alerts.ArchiveEntry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if e.What != "" || !codeExts[strings.ToLower(path.Ext(strings.ReplaceAll(e.Name, `\`, "/")))] {
			return false
		}
	}
	return true
}

// addMine counts a staged file as the program's own code, by folder.
func addMine(mine map[string]*alerts.Unpacked, st *alerts.Staged) {
	dir := filepath.Dir(st.Path)
	u := mine[dir]
	if u == nil {
		u = &alerts.Unpacked{Dir: dir}
		mine[dir] = u
	}
	u.Files++
	u.Size += st.Size
}

// unpackedList is mine in order of folder.
func unpackedList(mine map[string]*alerts.Unpacked) []alerts.Unpacked {
	var out []alerts.Unpacked
	for _, u := range mine {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// selfCopy recognises a copy of the program's own file (by size, then
// checksum), e.g. one it put in a startup folder.
type selfCopy struct {
	path string
	size int64
	crc  uint32
	done bool
	ok   bool
}

func newSelfCopy(image string) *selfCopy {
	s := &selfCopy{path: image, size: -1}
	if image == "" {
		return s
	}
	if fi, err := os.Stat(image); err == nil {
		s.size = fi.Size()
	}
	return s
}

func (s *selfCopy) is(p string, size int64) bool {
	if s.size <= 0 || size != s.size || paths.Same(p, s.path) {
		return false
	}
	if !s.done {
		s.done = true
		s.crc, s.ok = fileCRC(s.path)
	}
	if !s.ok {
		return false
	}
	c, ok := fileCRC(p)
	return ok && c == s.crc
}
