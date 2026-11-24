package procinfo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenFilesAndStartedAtOfSelf(t *testing.T) {
	p := filepath.Join(t.TempDir(), "held.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files, err := OpenFiles(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(p)
	found := false
	for _, x := range files {
		found = found || x == p || x == real
	}
	if !found {
		t.Errorf("%s not among the open files %v", p, files)
	}
	at, err := StartedAt(uint32(os.Getpid()))
	if err != nil || time.Since(at) < 0 || time.Since(at) > time.Hour {
		t.Errorf("started at %v (%v)", at, err)
	}
}

func TestParseLsofFiles(t *testing.T) {
	out := "p123\nfcwd\ntDIR\nn/Users/u\nf3\ntREG\nn/private/tmp/x/out.zip\nf4\ntIPv4\nn10.0.0.1:5->1.2.3.4:443\nf5\ntREG\nn/dev/null\n"
	got := parseLsofFiles(out)
	if len(got) != 2 || got[0] != "/private/tmp/x/out.zip" {
		t.Errorf("got %v", got)
	}
}
