package install

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// `aba uninstall` run from the installed copy can't delete its own folder, so
// it leaves that to a helper that waits for it to exit. The folder name has
// spaces, and the window may sit at "Press Enter to close" for a while first.
func TestDeleteDirAfterExitWaitsForTheFolderToBeFree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "File Access Monitor")
	if err := os.MkdirAll(filepath.Join(dir, "updates"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"aba.exe", "famsvc.exe", `updates\rollback.exe`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Like a program that is still running: its file can't be deleted yet.
	busy, err := os.Open(filepath.Join(dir, "aba.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deleteDirAfterExit(dir); err != nil {
		busy.Close()
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(filepath.Join(dir, "aba.exe")); err != nil {
		busy.Close()
		t.Fatalf("the file in use should still be there: %v", err)
	}
	busy.Close()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s is still there 20 s after it became free", dir)
}

func TestDeleteDirAfterExitRefusesOddPaths(t *testing.T) {
	// The path goes into a cmd.exe command line. Program Files never has these
	// characters in it; anything that does is not deleted that way.
	for _, dir := range []string{`C:\x" & calc & "`, `C:\100%`, `C:\a&b`} {
		if err := deleteDirAfterExit(dir); err == nil {
			t.Errorf("%s: want a refusal", dir)
		}
	}
}
