package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// The fake stealer for `aba test` is written into Temp by a process running
// as administrator. Until it has started, nothing may be able to change it.
func TestTestReaderCantBeSwapped(t *testing.T) {
	self, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), `System32\ping.exe`))
	if err != nil {
		t.Skip(err)
	}
	// ping treats "test-reader" as a host name, fails to resolve it and exits:
	// enough to see that it was started.
	r, err := startTestReader(self, "-n")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.PID == 0 {
		t.Fatal("not started")
	}
	if lvl, err := procinfo.IntegrityLevel(r.PID); err == nil && lvl >= procinfo.IntegrityHigh {
		t.Fatalf("the fake stealer runs with admin rights (integrity 0x%x)", lvl)
	}
	// While it's held: no writing, no replacing, no deleting, no renaming.
	if err := os.WriteFile(r.Path, []byte("something else"), 0o644); err == nil {
		t.Fatal("the file could be overwritten")
	}
	if err := os.Remove(r.Path); err == nil {
		t.Fatal("the file could be deleted")
	}
	if err := os.Rename(r.Path, r.Path+".moved"); err == nil {
		t.Fatal("the file could be renamed")
	}
	path := r.Path
	r.Close()
	for i := 0; i < 40; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		os.Remove(path)
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the fake stealer's file was left behind")
}
