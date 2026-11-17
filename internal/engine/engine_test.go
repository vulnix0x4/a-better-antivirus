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

func TestLearningModeTakesNoAction(t *testing.T) {
	e, f := setup("strict")
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	e.HandleAccess(ev(300, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 1))
	a := only(f)
	if len(f.suspended) != 0 || f.isolated != 0 || len(a.Actions) != 0 || !a.Learning {
		t.Fatalf("learning mode acted: %+v", a)
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
	if e.DecideInstant(100, desktopBait) {
		t.Error("learning mode must not freeze")
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
	if a == nil || !a.BeforeRead || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.suspended) != 0 {
		t.Fatalf("already frozen mid-open; must not suspend again (suspend counts stack): %v", f.suspended)
	}
	if len(f.state.Frozen) != 1 || f.state.Frozen[0].PID != 100 {
		t.Fatalf("state should record the pre-frozen pid: %+v", f.state.Frozen)
	}
	if !strings.Contains(a.Title, "tried to open") || !strings.Contains(a.Summary, "before it could read") {
		t.Fatalf("title/summary: %q / %q", a.Title, a.Summary)
	}
}
