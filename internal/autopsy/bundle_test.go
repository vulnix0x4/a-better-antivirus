package autopsy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Old evidence gives way to new: the memory copies of the oldest folders
// first, never what the autopsy found, and never the folder just written.
func TestPruneEvidence(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	mk := func(id string, memory, staged int) string {
		dir := filepath.Join(root, id)
		write := func(rel string, n int) {
			p := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write("autopsy.json", 10)
		if memory > 0 {
			write("memory/pid-1.bin", memory)
		}
		if staged > 0 {
			write("staged/00-loot.zip", staged)
		}
		return dir
	}
	oldest := mk("20261101-090000-aaaa", 400, 100)
	middle := mk("20261102-090000-bbbb", 400, 100)
	newest := mk("20261103-090000-cccc", 400, 100)
	has := func(dir, rel string) bool { _, err := os.Stat(filepath.Join(dir, rel)); return err == nil }

	// 1530 bytes in all, 1200 allowed: the oldest memory copy (400) goes.
	removed := pruneEvidence(root, newest, 1200, now)
	if len(removed) != 1 || has(oldest, "memory") || !has(oldest, "staged") || !has(middle, "memory") {
		t.Fatalf("removed %v", removed)
	}
	if !has(oldest, "autopsy.json") || !has(oldest, "removed.txt") {
		t.Error("the oldest folder lost its findings, or says nothing about what went")
	}
	// 500 allowed: both older memory copies and staged folders go; the newest
	// is kept whole even though it alone is over.
	pruneEvidence(root, newest, 500, now)
	if has(middle, "memory") || has(oldest, "staged") || has(middle, "staged") {
		t.Error("older folders kept their big parts")
	}
	if !has(newest, "memory") || !has(newest, "staged") || !has(middle, "autopsy.json") {
		t.Error("the newest folder, or an older one's findings, was touched")
	}
	// Under the limit: nothing happens.
	if r := pruneEvidence(root, newest, 1<<20, now); len(r) != 0 {
		t.Errorf("removed %v with room to spare", r)
	}
}
