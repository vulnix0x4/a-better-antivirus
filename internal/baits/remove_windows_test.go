package baits

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// plant writes a file and returns it as a file ABA created, unchanged since.
func plant(t *testing.T, path string) config.BaitFile {
	t.Helper()
	if err := os.WriteFile(path, []byte("bait"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return config.BaitFile{Path: path, Size: fi.Size(), ModTime: fi.ModTime(), Created: true}
}

// holdNoDelete opens path the way most programs do (Go's and C's plain opens):
// without letting anyone delete it meanwhile.
func holdNoDelete(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A reader that has only just let go of the bait (one that was frozen, then
// resumed or killed) used to make the removal fail, silently, leaving a decoy
// behind that ABA no longer knew about.
func TestRemoveWaitsForAReaderToLetGo(t *testing.T) {
	dir := t.TempDir()
	f := plant(t, filepath.Join(dir, "bank logins.txt"))
	h := holdNoDelete(t, f.Path)
	go func() { time.Sleep(500 * time.Millisecond); windows.CloseHandle(h) }()
	bs := &config.BaitState{ID: "custom-x", Files: []config.BaitFile{f}}
	if err := Remove(bs); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Lstat(f.Path); !os.IsNotExist(err) {
		t.Fatalf("bait still there after Remove (%v)", err)
	}
}

// One that keeps it open makes Remove fail (so it's reported and the bait stays
// on record), and the record keeps only what's still there: a file that was
// deleted must not look like one someone else deleted.
func TestRemoveThatFailsKeepsWhatIsLeft(t *testing.T) {
	dir := t.TempDir()
	gone := plant(t, filepath.Join(dir, "a.txt"))
	held := plant(t, filepath.Join(dir, "b.txt"))
	h := holdNoDelete(t, held.Path)
	defer windows.CloseHandle(h)
	bs := &config.BaitState{ID: "decoy-x", Files: []config.BaitFile{gone, held}}
	if err := Remove(bs); err == nil {
		t.Fatal("Remove succeeded while a program kept the file open without sharing delete")
	}
	if len(bs.Files) != 1 || bs.Files[0].Path != held.Path {
		t.Fatalf("files on record after a failed remove: %+v, want only %s", bs.Files, held.Path)
	}
	if _, err := os.Lstat(gone.Path); !os.IsNotExist(err) {
		t.Fatalf("%s should have been deleted (%v)", gone.Path, err)
	}
}

// Kept says which files a removal leaves in place, and why.
func TestKeptNamesChangedAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	same := plant(t, filepath.Join(dir, "same.txt"))
	changed := plant(t, filepath.Join(dir, "changed.txt"))
	theirs := plant(t, filepath.Join(dir, "theirs.txt"))
	theirs.Created = false
	if err := os.WriteFile(changed.Path, []byte("rewritten by an app"), 0o644); err != nil {
		t.Fatal(err)
	}
	kept := Kept(&config.BaitState{Files: []config.BaitFile{same, changed, theirs}})
	if len(kept) != 2 || !strings.HasPrefix(kept[0], changed.Path+" (it changed since") || !strings.HasPrefix(kept[1], theirs.Path+" (it isn't one ABA made") {
		t.Fatalf("Kept = %q", kept)
	}
}
