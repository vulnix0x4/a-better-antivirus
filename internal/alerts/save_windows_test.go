package alerts

import (
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// What happened in the VM: an instant freeze, `aba resume` 1.5 s later,
// then the autopsy finished and the service saved the alert again. The
// resolution must survive that save, and the autopsy be added. (The data
// folder is a temporary one: see paths.DataDir.)
func TestLateServiceSaveKeepsTheResolution(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	a := &Alert{ID: "20261124-120000-abcd", Time: time.Now(), Kind: KindRead, Tier: config.TierCritical, Status: "open",
		Baits: []BaitHit{{Path: `C:\Users\bob\Desktop\passwords.txt`, Access: "read"}}}
	a.AddAction(config.ActionFreeze, nil, "2 process(es) frozen")
	a.AddAction(config.ActionBlockProgram, nil, `C:\Users\bob\Downloads\x.exe`)
	if err := SaveFromService(a); err != nil {
		t.Fatal(err)
	}
	// `aba resume <id>`, through the CLI.
	if _, err := Update(a.ID, func(x *Alert) { x.Status, x.Note = "resolved", "let run again by you (nothing trusted)" }); err != nil {
		t.Fatal(err)
	}
	// The service, later, with its in-memory copy (still "open").
	cp := *a
	cp.Autopsy = &Autopsy{Answer: AnswerNoSign, Headline: "No sign it read anything real."}
	cp.Baits = append(append([]BaitHit(nil), a.Baits...), BaitHit{Path: `C:\Users\bob\.aws\credentials`, Access: "read"})
	if err := SaveFromService(&cp); err != nil {
		t.Fatal(err)
	}
	got, err := Load(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "resolved" || got.Note != "let run again by you (nothing trusted)" {
		t.Fatalf("the resolution was overwritten: %s / %s", got.Status, got.Note)
	}
	if got.Autopsy == nil || len(got.Baits) != 2 || len(got.Actions) != 2 {
		t.Fatalf("the service's additions: %+v", got)
	}
}
