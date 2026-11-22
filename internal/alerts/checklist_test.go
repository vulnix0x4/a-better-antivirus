package alerts

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

func TestChecklist(t *testing.T) {
	read := Checklist(&Alert{Kind: KindRead, Process: &Process{SHA256: "abc"}})
	clip := Checklist(&Alert{Kind: KindClipper})
	for name, steps := range map[string][]string{"read": read, "clipper": clip} {
		if !contains(steps, platform.CleanupStep) {
			t.Errorf("%s: no cleanup step for this platform: %q", name, steps)
		}
		for _, s := range steps {
			// "PC" is the Windows word: on a Mac or Linux it reads wrong.
			if platform.PC != "PC" && (strings.Contains(s, "Windows") || strings.Contains(s, " PC")) {
				t.Errorf("%s: Windows wording on %s: %q", name, platform.PC, s)
			}
		}
	}
	if !strings.Contains(read[0], "offline") || !strings.Contains(read[len(read)-1], "virustotal.com/gui/file/abc") {
		t.Errorf("read checklist: %q", read)
	}
	if !strings.Contains(clip[0], "Don't send crypto") || !strings.Contains(clip[1], "transfers") {
		t.Errorf("clipper checklist: %q", clip)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
