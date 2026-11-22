package engine

import (
	"reflect"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

func TestOriginCandidates(t *testing.T) {
	py := `C:\Users\b\AppData\Local\Programs\Python\Python312\python.exe`
	p := &alerts.Process{Image: py, CommandLine: `"` + py + `" C:\Users\b\Downloads\grab.py`,
		Parents: []procinfo.Parent{{PID: 2, Exited: true}, {PID: 3, Image: `C:\Users\b\Downloads\setup.exe`}}}
	want := []string{`C:\Users\b\Downloads\grab.py`, py, `C:\Users\b\Downloads\setup.exe`}
	if got := originCandidates(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A program that isn't a script host: its arguments aren't what runs.
	p = &alerts.Process{Image: `C:\Temp\x.exe`, CommandLine: `C:\Temp\x.exe C:\Users\b\Downloads\a.txt`}
	if got := originCandidates(p); !reflect.DeepEqual(got, []string{`C:\Temp\x.exe`}) {
		t.Fatalf("got %q", got)
	}
}
