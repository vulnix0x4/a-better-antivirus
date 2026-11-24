package autopsy

// Files that appeared while the program ran, where stealers stage what they
// collect: a folder in Temp, an archive in the program's own folder. A file
// that appeared there isn't proof the program made it (anything else
// running could have); one it holds open is.

import (
	"io/fs"
	"os"
	"path/filepath"
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
// the list of folders actually looked through.
func findStaged(dirs []Dir, since time.Time, skip map[string]bool, evidence string) (out []*alerts.Staged, where []string) {
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
	return out, where
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
