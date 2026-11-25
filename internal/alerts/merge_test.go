package alerts

import (
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// The service's later copy of an alert keeps what the CLI wrote meanwhile.
func TestMergeKeepsTheCLIsAnswer(t *testing.T) {
	t0 := time.Now()
	svc := &Alert{ID: "x", Status: "open", Baits: []BaitHit{{Path: `C:\b1`, Access: "read"}, {Path: `C:\b2`, Access: "read"}},
		Autopsy: &Autopsy{Answer: AnswerNoSign}}
	svc.Actions = []ActionResult{{Action: config.ActionFreeze, OK: true, Detail: "2 process(es) frozen", Time: t0}}
	disk := &Alert{ID: "x", Status: "resolved", Note: "let run again by you (nothing trusted)", Baits: []BaitHit{{Path: `C:\b1`, Access: "read"}},
		Actions: []ActionResult{{Action: config.ActionFreeze, OK: true, Detail: "2 process(es) frozen", Time: t0}, {Action: config.ActionKill, OK: true, Detail: "by you", Time: t0.Add(time.Second)}}}
	got := Merge(disk, svc)
	if got.Status != "resolved" || got.Note != disk.Note {
		t.Fatalf("resolution lost: %s / %s", got.Status, got.Note)
	}
	if len(got.Actions) != 2 || !got.Did(config.ActionKill) || len(got.Baits) != 2 || got.Autopsy == nil || got.Autopsy.Answer != AnswerNoSign {
		t.Fatalf("merged: %+v", got)
	}
	// Evidence the CLI saved before ending the program stays with the
	// service's later findings.
	disk.Autopsy = &Autopsy{Evidence: `C:\ProgramData\x\evidence\x`, MemoryImage: true}
	if got := Merge(disk, svc); got.Autopsy.Evidence == "" || !got.Autopsy.MemoryImage || got.Autopsy.Answer != AnswerNoSign {
		t.Fatalf("autopsy: %+v", got.Autopsy)
	}
	// Nothing written meanwhile: the service's copy as it is.
	open := &Alert{ID: "x", Status: "open"}
	if got := Merge(open, svc); got.Status != "open" || len(got.Actions) != 1 {
		t.Fatalf("plain: %+v", got)
	}
}
