package baits

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// legacyMarkers identify baits planted by the original PowerShell honeypot
// script, so we adopt (and later clean up) them as our own.
var legacyMarkers = []string{"j.marsh.1987@outlook.com"}

// Create plants a bait and returns its state. Existing files are adopted, not
// overwritten (the user may have customised them). Requires admin for audit rules.
func Create(s Spec, u config.UserInfo, g *Gen) (*config.BaitState, error) {
	bs := &config.BaitState{ID: s.ID, Name: s.Name, Kind: s.Kind, Status: "ok", CreatedAt: time.Now()}
	created := map[string]bool{}
	for _, f := range s.Files(u) {
		dir := filepath.Dir(f.Path)
		if top := topMissingDir(dir); top != "" && !created[top] {
			created[top] = true
			bs.CreatedDirs = append(bs.CreatedDirs, top)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return bs, fmt.Errorf("%s: %w", dir, err)
		}
		bf := config.BaitFile{Path: f.Path, Audit: f.Audit}
		if b, err := os.ReadFile(f.Path); err == nil {
			// Adopt an existing file (e.g. from the original honeypot script).
			if f.Text {
				bf.Text = string(b)
			}
			for _, m := range legacyMarkers {
				if strings.Contains(string(b), m) {
					bf.Created = true
				}
			}
		} else {
			data := f.Gen(g)
			if err := os.WriteFile(f.Path, data, 0o644); err != nil {
				return bs, fmt.Errorf("%s: %w", f.Path, err)
			}
			bf.Created = true
			if f.Text {
				bf.Text = string(data)
			}
			ageFile(f.Path)
			ownedBy(f.Path, u.SID)
		}
		if f.Audit {
			if err := winsec.SetBaitAudit(f.Path); err != nil {
				return bs, fmt.Errorf("audit rule on %s: %w", f.Path, err)
			}
		}
		if fi, err := os.Stat(f.Path); err == nil {
			bf.Size, bf.ModTime = fi.Size(), fi.ModTime()
		}
		bs.Files = append(bs.Files, bf)
	}
	// Folders ABA made: owned by you and older than what's in them, like a
	// real app's. (Last, because creating a file updates its folder's dates.)
	for _, d := range bs.CreatedDirs {
		ageTree(d, u.SID)
	}
	return bs, nil
}

// topMissingDir returns the highest ancestor of dir that doesn't exist yet.
func topMissingDir(dir string) string {
	top := ""
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			return top
		}
		top = d
		if filepath.Dir(d) == d {
			return top
		}
	}
}

// Blending in.
//
// A bait has to pass for an ordinary file at a glance, because a stealer can
// look at a file's properties (a folder listing gives them all) without
// opening it, and so without tripping anything. Things real files have that a
// freshly planted one doesn't, unless ABA takes care of them:
//
//   - an age: nothing a browser wrote was created this minute;
//   - three different timestamps: created, modified and last opened are never
//     the same instant on a file that's been used;
//   - a folder older than the files in it;
//   - you as the owner: files created by an installer running as
//     administrator belong to "Administrators", which nothing on your Desktop
//     normally does;
//   - the same indexing setting as their neighbours. (ABA used to mark baits
//     "don't index" to keep Windows Search away, which made them the only such
//     files in Documents. Windows Search is ignored by name anyway.)

func fileTime(t time.Time) *windows.Filetime {
	ft := windows.NsecToFiletime(t.UnixNano())
	return &ft
}

func setTimes(path string, created, accessed, written time.Time) {
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.SetFileTime(h, fileTime(created), fileTime(accessed), fileTime(written))
}

func getTimes(path string) (created, written time.Time, ok bool) {
	var d windows.Win32FileAttributeData
	p, err := windows.UTF16PtrFromString(path)
	if err != nil || windows.GetFileAttributesEx(p, windows.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&d))) != nil {
		return created, written, false
	}
	return time.Unix(0, d.CreationTime.Nanoseconds()), time.Unix(0, d.LastWriteTime.Nanoseconds()), true
}

func jitter() time.Duration { return time.Duration(rint(1_000_000_000)) } // up to a second, to the 100 ns

// ageFile backdates a new bait: created 1 to 14 months ago, last changed some
// time after that, last opened later still.
func ageFile(path string) {
	now := time.Now()
	created := now.Add(-time.Duration(30+rint(400))*24*time.Hour - time.Duration(rint(86400))*time.Second - jitter())
	age := now.Sub(created)
	written := created.Add(time.Duration(rint(int(age.Hours())*3/4+1))*time.Hour + jitter())
	accessed := written.Add(time.Duration(rint(int(now.Sub(written).Hours())/2+1))*time.Hour + jitter())
	setTimes(path, created, accessed, written)
}

// ageTree makes a folder ABA created (and the folders inside it) look as old
// as its contents: created a while before its oldest entry, last changed when
// its newest was. It returns the folder's creation time.
func ageTree(dir, ownerSID string) time.Time {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}
	}
	var oldest, newest time.Time
	note := func(c, w time.Time) {
		if !c.IsZero() && (oldest.IsZero() || c.Before(oldest)) {
			oldest = c
		}
		if w.After(newest) {
			newest = w
		}
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			c := ageTree(p, ownerSID)
			note(c, c)
			continue
		}
		if c, w, ok := getTimes(p); ok {
			note(c, w)
		}
	}
	if oldest.IsZero() {
		return time.Time{}
	}
	created := oldest.Add(-time.Duration(1+rint(30*24*60))*time.Minute - jitter())
	setTimes(dir, created, newest.Add(jitter()), newest.Add(jitter()))
	ownedBy(dir, ownerSID)
	return created
}

// ownedBy makes sid the owner of path, when it isn't already. (Needs the
// restore privilege, which an elevated installer and the service have.)
func ownedBy(path, sid string) {
	if sid == "" {
		return
	}
	want, err := windows.StringToSid(sid)
	if err != nil {
		return
	}
	if sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
		if cur, _, err := sd.Owner(); err == nil && cur != nil && cur.Equals(want) {
			return
		}
	}
	if winsec.EnablePrivilege("SeRestorePrivilege") != nil {
		return
	}
	windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, want, nil, nil, nil)
}

// indexedLikeFolder gives a bait the same "index this file" setting as the
// folder it's in (which is what any file created there gets).
func indexedLikeFolder(path string) {
	attrs := func(p string) (uint32, bool) {
		u, _ := windows.UTF16PtrFromString(p)
		a, err := windows.GetFileAttributes(u)
		return a, err == nil
	}
	fa, ok1 := attrs(path)
	da, ok2 := attrs(filepath.Dir(path))
	const noIndex = windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	if !ok1 || !ok2 || fa&noIndex == da&noIndex {
		return
	}
	u, _ := windows.UTF16PtrFromString(path)
	windows.SetFileAttributes(u, fa&^noIndex|da&noIndex)
}

// legacyEmptyDB is the size of the empty, table-less database older versions
// planted as "Login Data", "Cookies"…: one page, on every install.
const legacyEmptyDB = 4096

// Blend brings the baits of an install made by an older version in line with
// the list above: owner and indexing, and real-looking databases in place of
// the empty ones (see sqlite.go). Only files ABA created itself and nothing
// has written to since. It reports whether it rewrote anything.
func Blend(bs *config.BaitState, s Spec, u config.UserInfo, g *Gen) (changed bool) {
	gens := map[string]FileSpec{}
	if s.Files != nil {
		for _, f := range s.Files(u) {
			gens[strings.ToLower(f.Path)] = f
		}
	}
	for i := range bs.Files {
		f := &bs.Files[i]
		if !f.Created {
			continue
		}
		fi, err := os.Lstat(f.Path)
		if err != nil {
			continue
		}
		ownedBy(f.Path, u.SID)
		indexedLikeFolder(f.Path)
		untouched := fi.Size() == f.Size && fi.ModTime().Equal(f.ModTime)
		// Older versions gave a bait one timestamp for created, modified and
		// opened alike: spread them out.
		if c, w, ok := getTimes(f.Path); ok && untouched && c.Equal(w) {
			ageFile(f.Path)
			if fi2, err := os.Stat(f.Path); err == nil {
				f.ModTime, fi = fi2.ModTime(), fi2
				changed = true
			}
		}
		spec, known := gens[strings.ToLower(f.Path)]
		if !known || !untouched || f.Size != legacyEmptyDB {
			continue
		}
		data := spec.Gen(g)
		if len(data) == legacyEmptyDB || !strings.HasPrefix(string(data), "SQLite format 3") {
			continue
		}
		// Written in place: the file keeps its audit rule.
		if os.WriteFile(f.Path, data, 0o644) != nil {
			continue
		}
		ageFile(f.Path)
		if fi, err := os.Stat(f.Path); err == nil {
			f.Size, f.ModTime = fi.Size(), fi.ModTime()
		}
		changed = true
	}
	for _, d := range bs.CreatedDirs {
		// A folder newer than something in it is one ABA made in a hurry.
		newer := false
		dc, _, ok := getTimes(d)
		filepath.Walk(d, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if fi.IsDir() {
				ownedBy(p, u.SID)
			}
			if c, _, ok2 := getTimes(p); ok && ok2 && p != d && c.Before(dc) {
				newer = true
			}
			return nil
		})
		if newer {
			ageTree(d, u.SID)
		}
	}
	return changed
}

// Problem found by Check.
type Problem struct {
	File   string
	Kind   string // missing | no-audit | modified
	Detail string
}

// Check inspects a bait without reading its contents (reading would trip it).
func Check(bs *config.BaitState) []Problem {
	var out []Problem
	for _, f := range bs.Files {
		fi, err := os.Stat(f.Path)
		if errors.Is(err, os.ErrNotExist) {
			out = append(out, Problem{File: f.Path, Kind: "missing"})
			continue
		}
		if err != nil {
			continue
		}
		if f.Audit {
			if ok, err := winsec.HasBaitAudit(f.Path); err == nil && !ok {
				out = append(out, Problem{File: f.Path, Kind: "no-audit", Detail: "audit rule was stripped (an editor rewrote the file?)"})
			}
		}
		if f.Size != 0 && (fi.Size() != f.Size || !fi.ModTime().Equal(f.ModTime)) {
			out = append(out, Problem{File: f.Path, Kind: "modified", Detail: "contents changed"})
		}
	}
	return out
}

// Repair fixes problems: recreates missing files and re-applies audit rules.
func Repair(bs *config.BaitState, s Spec, u config.UserInfo, g *Gen, probs []Problem) error {
	specs := map[string]FileSpec{}
	for _, f := range s.Files(u) {
		specs[strings.ToLower(f.Path)] = f
	}
	var firstErr error
	for _, p := range probs {
		idx := -1
		for i := range bs.Files {
			if strings.EqualFold(bs.Files[i].Path, p.File) {
				idx = i
			}
		}
		if idx < 0 {
			continue
		}
		bf := &bs.Files[idx]
		switch p.Kind {
		case "missing":
			fs, ok := specs[strings.ToLower(p.File)]
			if !ok {
				continue
			}
			os.MkdirAll(filepath.Dir(p.File), 0o755)
			data := []byte(bf.Text)
			if data == nil || !fs.Text {
				data = fs.Gen(g)
			}
			if err := os.WriteFile(p.File, data, 0o644); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			ageFile(p.File)
			ownedBy(p.File, u.SID)
			bf.Created = true
			if fs.Text {
				bf.Text = string(data)
			}
			fallthrough
		case "no-audit":
			if bf.Audit {
				if err := winsec.SetBaitAudit(p.File); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			if fi, err := os.Stat(p.File); err == nil {
				bf.Size, bf.ModTime = fi.Size(), fi.ModTime()
			}
		case "modified":
			// Something (you, or a real app) wrote to it: from now on we never
			// delete it, we only take our audit rule off when removing.
			bf.Created = false
			if fi, err := os.Stat(p.File); err == nil {
				bf.Size, bf.ModTime = fi.Size(), fi.ModTime()
			}
		}
	}
	return firstErr
}

// Remove takes a bait away: audit rules first (so deleting doesn't alert),
// then files ABA created, then folders it created if they're now empty.
// Adopted files the user made themselves are kept.
func Remove(bs *config.BaitState) error {
	var firstErr error
	for _, f := range bs.Files {
		if f.Audit {
			winsec.ClearAudit(f.Path)
		}
		// Only delete a file if it's still exactly what we planted. If anything
		// rewrote it (e.g. the real app moved in and saved its own data there),
		// it's no longer ours: keep it.
		if f.Created && unchanged(f) {
			if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
				firstErr = err
			} else if err == nil {
				// The name stays visible until every handle closes (the service's
				// instant-freeze guard lets go a moment after the delete), so wait
				// for it: callers report "removed" right after this returns.
				for try := 0; try < 20; try++ {
					if _, err := os.Lstat(f.Path); errors.Is(err, os.ErrNotExist) {
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
		}
	}
	// A just-deleted file can linger for a moment while another handle on it
	// closes (e.g. ABA's own instant-freeze guard letting go), so retry briefly.
	for i := len(bs.CreatedDirs) - 1; i >= 0; i-- {
		for try := 0; try < 5; try++ {
			if removeEmptyTree(bs.CreatedDirs[i]) {
				break
			}
			if _, err := os.Stat(bs.CreatedDirs[i]); err != nil || !onlyPendingDeletes(bs.CreatedDirs[i], bs) {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
	}
	return firstErr
}

// removeEmptyTree deletes dir and empty subdirectories, keeping anything with
// files in it (e.g. if the real app has since moved in).
func removeEmptyTree(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	// Our own files (including fake leveldb LOCK files) were already deleted by
	// Remove; anything left belongs to someone else (e.g. the real app) and
	// keeps the folder.
	empty := true
	for _, e := range entries {
		if e.IsDir() && removeEmptyTree(filepath.Join(dir, e.Name())) {
			continue
		}
		empty = false
	}
	if empty {
		return os.Remove(dir) == nil
	}
	return false
}

// Index maps lowercase file paths to bait IDs, for event lookup.
func Index(st *config.State) map[string]string {
	m := map[string]string{}
	for id, bs := range st.Baits {
		if bs.Status == "retired" {
			continue
		}
		for _, f := range bs.Files {
			if f.Audit {
				m[paths.Key(f.Path)] = id
			}
		}
	}
	return m
}

// unchanged reports whether a bait file still has the size and timestamp we recorded.
func unchanged(f config.BaitFile) bool {
	fi, err := os.Stat(f.Path)
	if err != nil {
		return true // already gone; nothing to protect
	}
	return fi.Size() == f.Size && fi.ModTime().Equal(f.ModTime)
}

// Retire removes a decoy whose real app is now installed, plus any baits
// living inside it (e.g. fake MetaMask inside a fake browser the user now
// really uses). Returns the IDs retired.
func Retire(st *config.State, u config.UserInfo, id, why string) []string {
	bs := st.Baits[id]
	if bs == nil || bs.Status == "retired" {
		return nil
	}
	var out []string
	if spec, ok := ByID(id); ok && spec.Root != nil {
		root := spec.Root(u)
		for otherID, other := range st.Baits {
			if otherID == id || other.Status == "retired" || len(other.Files) == 0 {
				continue
			}
			if paths.Under(other.Files[0].Path, root) {
				Remove(other)
				other.Status, other.StatusNote, other.RetiredAt = "retired", HostRetired+why, time.Now()
				out = append(out, otherID)
			}
		}
	}
	Remove(bs)
	bs.Status, bs.StatusNote, bs.RetiredAt = "retired", why, time.Now()
	return append(out, id)
}

// HostRetired starts the status note of a bait retired only because the decoy
// it lived in was.
const HostRetired = "its host decoy was retired: "

// RecentlyRetired counts decoys retired in their own right within d.
func RecentlyRetired(st *config.State, d time.Duration) int {
	n := 0
	for _, bs := range st.Baits {
		if bs.Status == "retired" && !bs.RetiredAt.IsZero() && time.Since(bs.RetiredAt) < d && !strings.HasPrefix(bs.StatusNote, HostRetired) {
			n++
		}
	}
	return n
}

// onlyPendingDeletes reports whether everything left under dir is one of our
// own bait files (i.e. waiting to vanish), so it's worth retrying.
func onlyPendingDeletes(dir string, bs *config.BaitState) bool {
	ours := map[string]bool{}
	for _, f := range bs.Files {
		if f.Created {
			ours[paths.Key(f.Path)] = true
		}
	}
	only := true
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && !ours[paths.Key(p)] {
			only = false
		}
		return nil
	})
	return only
}
