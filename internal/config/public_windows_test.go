package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The data folder's permissions, on a real folder: after locking, a program
// without admin rights can't read what's in it (including files that were
// there before), but can read the public corner.
func TestLockedFolderIsUnreadableWithoutAdmin(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("this test is about what a non-admin program can read")
	}
	dir := filepath.Join(t.TempDir(), "FileAccessMonitor")
	public := filepath.Join(dir, "public")
	os.MkdirAll(filepath.Join(dir, "alerts"), 0o755)
	state := filepath.Join(dir, "state.json")
	alert := filepath.Join(dir, "alerts", "a.json")
	os.WriteFile(state, []byte(`{"baits":{}}`), 0o644) // there before the lock, like on an upgrade
	os.WriteFile(alert, []byte(`{}`), 0o644)
	// Whatever happens, hand the folder back so the test can clean up.
	defer SetSDDL(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")

	if err := lockDir(dir, public); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{state, alert} {
		if _, err := os.ReadFile(p); !os.IsPermission(err) {
			t.Errorf("%s is still readable without admin rights (err=%v)", p, err)
		}
	}
	if _, err := os.ReadDir(dir); !os.IsPermission(err) {
		t.Errorf("the folder can still be listed (err=%v)", err)
	}
	if _, err := os.ReadDir(public); err != nil {
		t.Errorf("the public corner should be readable: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(dir, "does-not-exist.json")); !os.IsNotExist(err) {
		t.Errorf("a missing file should read as missing, so `aba` can tell \"not installed\": %v", err)
	}
}
