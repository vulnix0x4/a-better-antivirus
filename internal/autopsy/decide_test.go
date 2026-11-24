package autopsy

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

var (
	start  = time.Date(2026, 11, 23, 14, 0, 0, 0, time.Local)
	baitAt = start.Add(10 * time.Second)
)

func watchedAll() []recorder.Coverage {
	return []recorder.Coverage{
		{Store: "chrome-profile", Name: "your Chrome", Kind: baits.StoreBrowser, Files: 4, Watched: true, Since: start.Add(-time.Hour)},
		{Store: "exodus", Name: "your Exodus wallet", Kind: baits.StoreWallet, Files: 1, Watched: true, Since: start.Add(-time.Hour)},
		{Store: "telegram", Name: "your Telegram Desktop session", Kind: baits.StoreSession, Absent: true},
	}
}

func run(f facts) *alerts.Autopsy {
	a := &alerts.Autopsy{}
	decide(f, a)
	return a
}

func TestAnswerRead(t *testing.T) {
	f := facts{recorderOn: true, start: start, baitAt: baitAt, res: recorder.Result{
		Stores: watchedAll(),
		Reads: []recorder.Read{{Store: "chrome-profile", StoreName: "your Chrome", Kind: baits.StoreBrowser, Path: "/u/Chrome/Default/Login Data", First: start.Add(6 * time.Second), PID: 900, Count: 1},
			{Store: "chrome-profile", StoreName: "your Chrome", Kind: baits.StoreBrowser, Path: "/u/Chrome/Default/Cookies", First: start.Add(7 * time.Second), PID: 900}},
	}}
	a := run(f)
	if a.Answer != alerts.AnswerRead {
		t.Fatalf("answer = %s (%s)", a.Answer, a.Headline)
	}
	if !strings.Contains(a.Headline, "your Chrome") {
		t.Errorf("headline = %q", a.Headline)
	}
	if len(a.Summary) == 0 || !strings.Contains(a.Summary[0], "Login Data, Cookies") || !strings.Contains(a.Summary[0], "4.0 s before it opened the bait") {
		t.Errorf("summary = %q", a.Summary)
	}
	if len(a.Steps) != 1 || !strings.Contains(a.Steps[0], "sign out of every site") {
		t.Errorf("steps = %q", a.Steps)
	}
}

func TestAnswerReadEvenWithoutRecorder(t *testing.T) {
	// It has the real wallet open right now: that's proof whatever the recorder says.
	f := facts{recorderOn: false, start: start, baitAt: baitAt, res: recorder.Result{Stores: watchedAll()},
		held: []alerts.StoreRead{{Store: "exodus", Name: "your Exodus wallet", Kind: baits.StoreWallet, Path: "/u/Exodus/exodus.wallet/seed.seco", At: baitAt, How: "it has it open right now"}}}
	a := run(f)
	if a.Answer != alerts.AnswerRead || !strings.Contains(a.Steps[0], "move the funds") {
		t.Errorf("answer %s steps %q", a.Answer, a.Steps)
	}
	if !strings.Contains(strings.Join(a.Summary, " "), "may have taken more") {
		t.Errorf("a read with the recorder off must say it may have taken more: %q", a.Summary)
	}
}

func TestAnswerNoSign(t *testing.T) {
	f := facts{recorderOn: true, start: start, baitAt: baitAt, res: recorder.Result{Stores: watchedAll()}}
	a := run(f)
	if a.Answer != alerts.AnswerNoSign {
		t.Fatalf("answer = %s: %v", a.Answer, a.Unsure)
	}
	if !strings.HasPrefix(a.Headline, "No sign it read anything real") || !strings.Contains(a.Headline, "your Chrome and your Exodus wallet") {
		t.Errorf("headline = %q", a.Headline)
	}
	if strings.Contains(strings.ToLower(a.Headline+strings.Join(a.Summary, "")), "nothing was taken") {
		t.Error("never say nothing was taken")
	}
	if !strings.Contains(a.Summary[0], "not proof") {
		t.Errorf("summary must say it isn't proof: %q", a.Summary)
	}
	if len(a.Steps) != 0 {
		t.Errorf("steps = %q", a.Steps)
	}
}

func TestCannotTellWhenRecorderOff(t *testing.T) {
	a := run(facts{recorderOn: false, recorderWhy: "it's switched off", start: start, baitAt: baitAt, res: recorder.Result{Stores: watchedAll()}})
	if a.Answer != alerts.AnswerUnknown || !strings.Contains(a.Headline, "flight recorder") {
		t.Errorf("answer %s headline %q", a.Answer, a.Headline)
	}
	if len(a.Steps) < 2 {
		t.Errorf("with nothing watched, every present store needs its advice: %q", a.Steps)
	}
}

func TestCannotTellWhenItStartedBeforeWatching(t *testing.T) {
	cov := watchedAll()
	cov[1].Watched, cov[1].Since, cov[1].Why = false, start.Add(time.Minute), "ABA only started watching it at 14:01:00, after the program started"
	a := run(facts{recorderOn: true, start: start, baitAt: baitAt, res: recorder.Result{Stores: cov}})
	if a.Answer != alerts.AnswerUnknown {
		t.Fatalf("answer = %s", a.Answer)
	}
	if !strings.Contains(a.Headline, "only started watching") {
		t.Errorf("headline = %q", a.Headline)
	}
	if len(a.Steps) != 1 || !strings.Contains(a.Steps[0], "Exodus") {
		t.Errorf("only the unwatched store needs advice: %q", a.Steps)
	}
	if !strings.Contains(strings.Join(a.Summary, " "), "no open of your Chrome") {
		t.Errorf("summary should say what was watched: %q", a.Summary)
	}
}

func TestCannotTellOnDoubtsLapsesUnknownStart(t *testing.T) {
	for name, f := range map[string]facts{
		"doubt": {recorderOn: true, start: start, res: recorder.Result{Stores: watchedAll(),
			Doubts: []recorder.Doubt{{Store: "chrome-profile", StoreName: "your Chrome", At: start.Add(time.Second), Why: "the system couldn't say which program opened it"}}}},
		"lapse":   {recorderOn: true, start: start, res: recorder.Result{Stores: watchedAll(), Lapses: []recorder.Lapse{{From: start, To: start, Why: "the kernel dropped events"}}}},
		"start":   {recorderOn: true, startWhy: "it had exited", res: recorder.Result{Stores: watchedAll()}},
		"forgot":  {recorderOn: true, start: start, res: recorder.Result{Stores: watchedAll(), Forgot: start.Add(time.Second)}},
		"staging": {recorderOn: true, start: start, res: recorder.Result{Stores: watchedAll()}, stagedReal: []stagedFact{{path: "/tmp/x/Login Data", store: "chrome-profile", name: "your Chrome", kind: baits.StoreBrowser, at: start.Add(3 * time.Second)}}},
	} {
		a := run(f)
		if a.Answer != alerts.AnswerUnknown {
			t.Errorf("%s: answer = %s", name, a.Answer)
		}
		if len(a.Steps) == 0 {
			t.Errorf("%s: no steps", name)
		}
	}
}

func TestStagedCopyItHoldsIsARead(t *testing.T) {
	f := facts{recorderOn: true, start: start, baitAt: baitAt, res: recorder.Result{Stores: watchedAll()},
		stagedReal: []stagedFact{{path: "/tmp/x/Login Data", store: "chrome-profile", name: "your Chrome", kind: baits.StoreBrowser, held: true, what: "/tmp/out.zip", at: start.Add(3 * time.Second)}}}
	if a := run(f); a.Answer != alerts.AnswerRead {
		t.Errorf("answer = %s", a.Answer)
	}
}

func TestNothingToWatch(t *testing.T) {
	a := run(facts{recorderOn: true, start: start, res: recorder.Result{Stores: []recorder.Coverage{{Store: "x", Name: "your X", Absent: true}}}})
	if a.Answer != alerts.AnswerNoSign || !strings.Contains(a.Headline, "none of the usual places") {
		t.Errorf("answer %s headline %q", a.Answer, a.Headline)
	}
}

func TestRelBait(t *testing.T) {
	if got := relBait(baitAt.Add(-1500*time.Millisecond), baitAt); got != "1.5 s before it opened the bait" {
		t.Error(got)
	}
	if got := relBait(baitAt.Add(20*time.Millisecond), baitAt); got != "20 ms after it opened the bait" {
		t.Error(got)
	}
}

// A store whose folder is watched but holds nothing isn't named as watched
// (there was nothing to take), and doesn't stand in the way of "no sign".
func TestEmptyWatchedStoreIsNotNamed(t *testing.T) {
	cov := append(watchedAll(), recorder.Coverage{Store: "aws-keys", Name: "your AWS keys", Kind: baits.StoreKeys, Watched: true, Files: 0})
	a := run(facts{recorderOn: true, start: start, res: recorder.Result{Stores: cov}})
	if a.Answer != alerts.AnswerNoSign || strings.Contains(a.Headline, "AWS") {
		t.Errorf("answer %s headline %q", a.Answer, a.Headline)
	}
}
