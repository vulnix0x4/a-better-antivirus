package trust

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// A sweep by a file tool (a scheduled tar of the home folder) can be trusted
// on Linux: by its exact command, in its folder, with every bait. Without
// the command or the folder it can't.
func TestSweepByBackupCommand(t *testing.T) {
	a := &alerts.Alert{ID: "x", Verdict: classify.Verdict{Swept: []string{"vivaldi", "electrum", "aws"}},
		Baits: []alerts.BaitHit{{ID: "vivaldi"}},
		Process: &alerts.Process{Image: "/usr/bin/tar", CommandLine: "tar czf /var/backups/home.tgz /home/u", Dir: "/home/u",
			Signature: provenance.Result{Signed: true, Valid: true, Signer: "tar"}}}
	r, why := Rule(a)
	if why != "" {
		t.Fatalf("not trustable: %s", why)
	}
	if r.CommandLine != a.Process.CommandLine || r.Dir != "/home/u" || r.Path != "/usr/bin/tar" || r.Signer != "tar" || len(r.Baits) != 0 {
		t.Fatalf("rule %+v", r)
	}
	if d := Describe(r, nil); !strings.Contains(d, "run in /home/u") || !strings.Contains(d, "all baits") {
		t.Fatalf("Describe: %s", d)
	}
	if OneClick(a) {
		t.Fatal("a command-pinned rule is never one click from the popup")
	}
	a.Process.Dir = ""
	if _, why := Rule(a); why == "" {
		t.Fatal("trusted with every bait without knowing the folder it ran in")
	}
	a.Process.Dir, a.Process.CommandLine = "/home/u", ""
	if _, why := Rule(a); why == "" {
		t.Fatal("trusted with every bait without knowing the command")
	}
}
