package engine

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/evtlog"
)

type fakeOps struct {
	mu        sync.Mutex
	sigs      map[string]authenticode.Result
	suspended []uint32
	resumed   []uint32
	killed    []uint32
	blocked   []string
	isolated  int
	saved     map[string]*alerts.Alert
	desktop   []string
	phone     []string
	retired   []string
	state     *config.State
	test      *TestRequest
	images    map[uint32]string
}

func newFake() *fakeOps {
	return &fakeOps{images: map[uint32]string{}, sigs: map[string]authenticode.Result{}, saved: map[string]*alerts.Alert{}, state: config.NewState()}
}

func (f *fakeOps) ImagePath(pid uint32) (string, error) {
	if img, ok := f.images[pid]; ok {
		return img, nil
	}
	return "", fmt.Errorf("n/a")
}
func (f *fakeOps) CreateTime(pid uint32) int64         { return 1 }
func (f *fakeOps) Verify(p string) authenticode.Result { return f.sigs[p] }
func (f *fakeOps) SuspendTree(pid uint32) ([]uint32, error) {
	f.suspended = append(f.suspended, pid)
	return []uint32{pid, pid + 1}, nil
}
func (f *fakeOps) Resume(p []uint32)                              { f.resumed = append(f.resumed, p...) }
func (f *fakeOps) KillTree(pid uint32) error                      { f.killed = append(f.killed, pid); return nil }
func (f *fakeOps) Forensics(uint32, *alerts.Process)              {}
func (f *fakeOps) BlockProgram(p string) error                    { f.blocked = append(f.blocked, p); return nil }
func (f *fakeOps) Isolate() error                                 { f.isolated++; return nil }
func (f *fakeOps) DisableAdapters() ([]string, error)             { return []string{"Wi-Fi"}, nil }
func (f *fakeOps) SaveAlert(a *alerts.Alert) error                { f.saved[a.ID] = a; return nil }
func (f *fakeOps) NotifyDesktop(a *alerts.Alert)                  { f.desktop = append(f.desktop, a.ID) }
func (f *fakeOps) NotifyPhone(a *alerts.Alert)                    { f.phone = append(f.phone, a.ID) }
func (f *fakeOps) RetireDecoy(id, why string)                     { f.retired = append(f.retired, id) }
func (f *fakeOps) PendingTest() *TestRequest                      { return f.test }
func (f *fakeOps) ClearTest()                                     { f.test = nil }
func (f *fakeOps) UserSession(uint32) bool                        { return true }
func (f *fakeOps) Elevated(pid uint32) bool                       { return pid == 777 }
func (f *fakeOps) IsSelf(img string) bool                         { return strings.HasSuffix(strings.ToLower(img), `\aba.exe`) }
func (f *fakeOps) Logf(string, ...any)                            {}
func (f *fakeOps) UpdateState(fn func(*config.State) error) error { return fn(f.state) }

const desktopBait = `C:\Users\bob\Desktop\passwords.txt`

func setup(preset string) (*Engine, *fakeOps) {
	f := newFake()
	e := New(f, 999)
	cfg := config.Default()
	cfg.ApplyPreset(preset)
	st := config.NewState()
	st.Baits["desktop-passwords"] = &config.BaitState{ID: "desktop-passwords", Name: "passwords.txt on the Desktop",
		Files: []config.BaitFile{{Path: desktopBait, Audit: true}}}
	st.Baits["discord"] = &config.BaitState{ID: "discord", Name: "Discord token store",
		Files: []config.BaitFile{{Path: `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, Audit: true}}}
	e.Configure(cfg, st)
	return e, f
}

func ev(pid uint32, image, obj string, mask uint32) *evtlog.ObjectAccess {
	return &evtlog.ObjectAccess{ProcessID: pid, ProcessName: image, ObjectName: obj, AccessMask: mask, Time: time.Now()}
}

func only(f *fakeOps) *alerts.Alert {
	for _, a := range f.saved {
		return a
	}
	return nil
}

func TestStealerIsFrozenAndBlocked(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	e.HandleAccess(ev(100, img, desktopBait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.resumed) != 0 || len(f.blocked) != 1 || f.isolated != 0 {
		t.Fatalf("ops: resumed=%v blocked=%v isolated=%d", f.resumed, f.blocked, f.isolated)
	}
	if len(f.state.Frozen) != 2 || len(f.state.Blocked) != 1 || len(f.phone) != 1 || len(f.desktop) != 1 {
		t.Fatalf("state/notify: %+v phone=%v", f.state, f.phone)
	}
	// The same stealer reading a second bait joins the same alert, no new responses.
	e.HandleAccess(ev(100, img, `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, 1))
	if len(f.saved) != 1 || len(a.Baits) != 2 || len(f.suspended) != 1 || len(f.desktop) != 1 {
		t.Fatalf("aggregation failed: alerts=%d baits=%d suspends=%d", len(f.saved), len(a.Baits), len(f.suspended))
	}
}

func TestSignedUserFolderAppIsUnfrozen(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	e.HandleAccess(ev(200, img, desktopBait, 1))
	a := only(f)
	if a.Tier != config.TierWarn || len(f.suspended) != 1 || len(f.resumed) != 2 || len(f.state.Frozen) != 0 || len(f.blocked) != 0 {
		t.Fatalf("tier=%s suspended=%v resumed=%v frozen=%v blocked=%v", a.Tier, f.suspended, f.resumed, f.state.Frozen, f.blocked)
	}
}

func TestStrictIsolates(t *testing.T) {
	e, f := setup("strict")
	e.HandleAccess(ev(300, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 1))
	if f.isolated != 1 || only(f).Tier != config.TierCritical || f.state.Isolation == nil {
		t.Fatalf("isolated=%d state=%+v", f.isolated, f.state.Isolation)
	}
}

func TestLearningModeStillStopsCritical(t *testing.T) {
	e, f := setup("strict")
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	e.HandleAccess(ev(300, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 1))
	a := only(f)
	if len(f.suspended) == 0 || f.isolated != 1 || a.Learning {
		t.Fatalf("critical reader must be stopped even while learning: %+v", a)
	}
}

func TestLearningModeHoldsBackWarn(t *testing.T) {
	e, f := setup("strict") // strict freezes warn-tier readers
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	img := `C:\Users\bob\AppData\Local\Programs\SyncTool\sync.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Sync Corp"}
	e.HandleAccess(ev(300, img, desktopBait, 1))
	a := only(f)
	if a.Tier != config.TierWarn || len(f.state.Frozen) != 0 || len(a.Actions) != 0 || !a.Learning {
		t.Fatalf("learning mode should only alert on warn: %+v", a)
	}
	if len(f.desktop) != 1 {
		t.Fatal("learning alerts must still reach the desktop (one-click trust)")
	}
}

func TestSignedSDKReadOfAWSIsNotAnAlert(t *testing.T) {
	e, f := setup("balanced")
	aws := `C:\Users\bob\.aws\credentials`
	st := config.NewState()
	st.Baits["aws"] = &config.BaitState{ID: "aws", Name: "AWS credentials", Files: []config.BaitFile{{Path: aws, Audit: true}}}
	e.Configure(e.cfg, st)
	oc := `C:\Users\bob\AppData\Roaming\npm\node_modules\@opencode\cli\bin\opencode.exe`
	f.sigs[oc] = authenticode.Result{Signed: true, Valid: true, Signer: "Anomaly Innovations, Inc"}
	e.HandleAccess(ev(400, oc, aws, 1))
	if len(f.saved) != 0 {
		t.Fatalf("signed SDK user reading ~/.aws must not alert: %+v", only(f))
	}
	e.HandleAccess(ev(401, `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`, aws, 1))
	if a := only(f); a == nil || a.Tier != config.TierCritical {
		t.Fatalf("unsigned reader of ~/.aws must still be critical: %+v", a)
	}
}

func TestRepeatAlertsDontPopUpAgain(t *testing.T) {
	e, f := setup("balanced") // warn = alert only
	img := `C:\Users\bob\AppData\Local\Programs\Tool\tool.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Tool Inc"}
	e.HandleAccess(ev(500, img, desktopBait, 1))
	e.HandleAccess(ev(501, img, desktopBait, 1))
	if len(f.saved) != 2 || len(f.desktop) != 1 {
		t.Fatalf("want 2 alerts saved, 1 notified; got %d saved, %d notified", len(f.saved), len(f.desktop))
	}
	e.HandleAccess(ev(502, `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`, desktopBait, 1))
	if len(f.desktop) != 2 {
		t.Fatal("a different program must still notify")
	}
}

func TestIgnoredAndUnrelatedEvents(t *testing.T) {
	e, f := setup("strict")
	e.HandleAccess(ev(1, `C:\Users\bob\Downloads\x.exe`, `C:\not\a\bait.txt`, 1))
	e.HandleAccess(ev(999, `C:\Program Files\File Access Monitor\famsvc.exe`, desktopBait, 1)) // ourselves
	def := `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe`
	f.sigs[def] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	e.HandleAccess(ev(5, def, desktopBait, 1))
	if len(f.saved) != 0 || len(f.suspended) != 0 {
		t.Fatalf("should be silent: alerts=%d suspended=%v", len(f.saved), f.suspended)
	}
}

func TestDecoyOwnerRetires(t *testing.T) {
	e, f := setup("strict")
	img := `C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Discord Inc."}
	e.HandleAccess(ev(400, img, `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, 1))
	a := only(f)
	if a.Kind != alerts.KindDecoyRetired || len(f.retired) != 1 || len(f.state.Frozen) != 0 || f.isolated != 0 {
		t.Fatalf("alert=%+v retired=%v frozen=%v", a, f.retired, f.state.Frozen)
	}
}

func TestTestModeNeverCutsNetwork(t *testing.T) {
	e, f := setup("strict")
	f.test = &TestRequest{PID: 500}
	e.HandleAccess(ev(500, `C:\Users\bob\AppData\Local\Temp\aba-test-reader.exe`, desktopBait, 1))
	a := only(f)
	if !a.Test || f.isolated != 0 || len(f.blocked) != 0 || !a.Did(config.ActionFreeze) || len(f.killed) != 1 || f.test != nil {
		t.Fatalf("test alert=%+v isolated=%d blocked=%v killed=%v", a, f.isolated, f.blocked, f.killed)
	}
}

func TestDeleteOnlyNotifies(t *testing.T) {
	e, f := setup("strict")
	e.HandleAccess(ev(600, `C:\Users\bob\Downloads\x.exe`, desktopBait, 0x10000))
	a := only(f)
	if a.Kind != alerts.KindDelete || len(a.Actions) != 0 || len(f.suspended) != 0 {
		t.Fatalf("delete: %+v suspended=%v", a, f.suspended)
	}
}

func TestProtectedProcessesNeverFrozen(t *testing.T) {
	e, f := setup("strict")
	// explorer.exe unsigned (prelim) would be "warn" -> strict freezes warn; must refuse.
	e.HandleAccess(ev(700, `C:\Windows\explorer.exe`, desktopBait, 1))
	if len(f.suspended) != 0 {
		t.Fatalf("froze explorer: %v", f.suspended)
	}
}

func TestInstantFreezeDecisions(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	stealer := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.images[100] = stealer
	f.images[200] = code
	f.images[300] = `C:\Windows\explorer.exe`
	f.sigs[code] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}

	if !e.DecideInstant(100, desktopBait) {
		t.Error("unsigned program in Temp should be frozen mid-open")
	}
	if e.DecideInstant(200, desktopBait) {
		t.Error("signed app should be let through (warn = notify only on balanced)")
	}
	if e.DecideInstant(300, desktopBait) {
		t.Error("explorer must never be frozen")
	}
	if e.DecideInstant(100, `C:\not\a\bait.txt`) {
		t.Error("only baits")
	}
	if e.DecideInstant(999, desktopBait) {
		t.Error("never ourselves")
	}
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	if !e.DecideInstant(100, desktopBait) {
		t.Error("learning mode must still freeze critical readers")
	}
	e.cfg.LearningUntil = time.Time{}
	e.cfg.InstantFreeze = false
	if e.DecideInstant(100, desktopBait) {
		t.Error("instant freeze switched off")
	}
	f.test = &TestRequest{PID: 100}
	if !e.DecideInstant(100, desktopBait) {
		t.Error("`aba test` always demonstrates the freeze")
	}
}

func TestHandleOpenUsesThePreFreeze(t *testing.T) {
	e, f := setup("balanced")
	f.images[100] = `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	e.HandleOpen(100, desktopBait, time.Now().Add(-70*time.Millisecond), []uint32{100})
	a := only(f)
	if a == nil || !a.Instant || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.suspended) != 0 {
		t.Fatalf("already frozen mid-open; must not suspend again (suspend counts stack): %v", f.suspended)
	}
	if len(f.state.Frozen) != 1 || f.state.Frozen[0].PID != 100 {
		t.Fatalf("state should record the pre-frozen pid: %+v", f.state.Frozen)
	}
	if !strings.Contains(a.Title, "opened") || !strings.Contains(a.Summary, "instant freeze") {
		t.Fatalf("title/summary: %q / %q", a.Title, a.Summary)
	}
}

func TestEventLogPathDoesNotDoubleFreezeInstantCatch(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	f.images[100] = img
	if !e.DecideInstant(100, desktopBait) {
		t.Fatal("should be claimed and frozen by the instant path")
	}
	e.HandleOpen(100, desktopBait, time.Now(), []uint32{100})
	// The same read then arrives through the event log.
	e.HandleAccess(ev(100, img, desktopBait, 1))
	if len(f.suspended) != 0 || len(f.saved) != 1 {
		t.Fatalf("double handling: suspended=%v alerts=%d", f.suspended, len(f.saved))
	}
	// A failed instant freeze must hand the process back to the normal path.
	f.images[101] = img
	e.DecideInstant(101, desktopBait)
	e.Unclaim(101)
	e.HandleAccess(ev(101, img, desktopBait, 1))
	if len(f.suspended) != 1 {
		t.Fatalf("unclaimed process should be frozen by the normal path: %v", f.suspended)
	}
}

func TestInstantSkipsSelfAndElevated(t *testing.T) {
	e, f := setup("balanced")
	f.images[100] = `D:\a\build\dist\aba.exe` // ABA's own CLI run from a build folder (CI hang)
	f.images[777] = `C:\Users\bob\Downloads\admin-tool.exe`
	if e.DecideInstant(100, desktopBait) {
		t.Error("ABA must never instant-freeze itself (e.g. `aba doctor`)")
	}
	if e.DecideInstant(777, desktopBait) {
		t.Error("elevated programs are left to the event-log path")
	}
	f.test = &TestRequest{PID: 100}
	if !e.DecideInstant(100, desktopBait) {
		t.Error("`aba test` reader (a copy of ABA) must still be frozen")
	}
}

func TestTestReaderLeavesFrozenList(t *testing.T) {
	e, f := setup("balanced")
	f.test = &TestRequest{PID: 500}
	e.HandleAccess(ev(500, `C:\Users\bob\AppData\Local\Temp\aba-test-1.exe`, desktopBait, 1))
	if len(f.killed) != 1 || len(f.state.Frozen) != 0 {
		t.Fatalf("killed=%v frozen=%+v: the killed test reader must not stay on the frozen list", f.killed, f.state.Frozen)
	}
}

// Resume a frozen process, it opens another bait within the aggregation
// window: the new instant freeze must get its own alert and state record,
// or `aba release` would never know about it.
func TestInstantRefreezeIsTracked(t *testing.T) {
	e, f := setup("balanced")
	f.images[100] = `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	e.DecideInstant(100, desktopBait)
	e.HandleOpen(100, desktopBait, time.Now(), []uint32{100})
	f.state.Frozen = nil // user resumed it (`aba resume`)
	e.DecideInstant(100, desktopBait)
	e.HandleOpen(100, `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, time.Now(), []uint32{100})
	if len(f.saved) != 2 || len(f.state.Frozen) != 1 {
		t.Fatalf("second freeze untracked: alerts=%d frozen=%+v", len(f.saved), f.state.Frozen)
	}
}
