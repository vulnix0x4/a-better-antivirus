package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Each test here is a way around ABA that used to work.

func signed(f *fakeOps, image, signer string) {
	f.sigs[image] = provenance.Result{Signed: true, Valid: true, Signer: signer}
}

// Calling your stealer svchost.exe (or explorer.exe, or conhost.exe) used to
// make it untouchable: "protected system processes" were recognised by name.
func TestImpostorSystemProcessIsFrozen(t *testing.T) {
	for _, img := range []string{
		`C:\Users\bob\AppData\Local\Temp\svchost.exe`,
		`C:\Users\bob\Downloads\explorer.exe`,
		`C:\Users\bob\AppData\Roaming\x\conhost.exe`,
		`C:\Windows\Tasks\svchost.exe`, // a part of the Windows folder anyone can write to
	} {
		e, f := setup("balanced")
		e.HandleAccess(ev(100, img, desktopBait, 1))
		a := only(f)
		if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || len(f.suspended) != 1 {
			t.Errorf("%s: %+v suspended=%v", img, a, f.suspended)
		}
		f.images[101] = img
		e.cfg.InstantFreeze = true
		if !e.DecideInstant(101, discordBait) {
			t.Errorf("%s must be frozen mid-open too", img)
		}
	}
	// The real ones stay off limits.
	e, f := setup("strict")
	for i, img := range []string{`C:\Windows\System32\svchost.exe`, `C:\Windows\explorer.exe`, `C:\Windows\System32\csrss.exe`} {
		signed(f, img, "Microsoft Windows")
		e.HandleAccess(ev(uint32(200+i), img, desktopBait, 1))
	}
	if len(f.suspended) != 0 {
		t.Fatalf("froze a real system process: %v", f.suspended)
	}
}

// An unsigned program inside the Windows folder used to be only "suspicious".
func TestUnsignedInWindowsFolderIsCritical(t *testing.T) {
	e, f := setup("balanced")
	e.HandleAccess(ev(100, `C:\Windows\tracing\helper.exe`, desktopBait, 1))
	if a := only(f); a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) {
		t.Fatalf("%+v", a)
	}
}

// A copy of ABA's own program was ignored whatever it did (recognised by its
// hash): start one, inject into it, read everything unseen.
func TestABAsOwnProgramIsNoDisguise(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Temp\aba.exe`
	e.HandleAccess(ev(100, img, desktopBait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !strings.Contains(a.Summary, "disguise") {
		t.Fatalf("an unelevated copy of ABA reading a bait: %+v", a)
	}
	if rule, why := trustRule(a); why == "" {
		t.Fatalf("that must never be trusted permanently: %+v", rule)
	}
	e.cfg.InstantFreeze = true
	f.images[101] = `C:\Program Files\File Access Monitor\aba.exe`
	if !e.DecideInstant(101, discordBait) {
		t.Fatal("even the installed aba.exe, when it isn't running as administrator")
	}
	// Running as administrator it's ABA's own tooling: nothing running as you can get inside that.
	e2, f2 := setup("balanced")
	f2.elevated[200] = true
	e2.HandleAccess(ev(200, `C:\Program Files\File Access Monitor\aba.exe`, desktopBait, 1))
	if len(f2.saved) != 0 || len(f2.suspended) != 0 {
		t.Fatalf("ABA's elevated tooling alerted: %+v", only(f2))
	}
}

// Opening a bait so that Windows doesn't pause you (a "ghost open") dodged
// instant freeze. It's now marked as evasion: critical, whoever does it.
func TestEvasionMarkMakesAnyReaderCritical(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	signed(f, code, "Microsoft Corporation")
	f.images[200] = code
	if e.DecideInstant(200, desktopBait) {
		t.Fatal("a signed app opening a bait normally is only a warning")
	}
	e.NoteEvasion(200, "it opened the bait in a way that keeps Windows from pausing it")
	if !e.DecideInstant(200, discordBait) {
		t.Fatal("after a ghost open it must be frozen")
	}
	e.HandleOpen(200, discordBait, time.Now(), []uint32{200})
	a := lastAlert(f)
	if a.Tier != config.TierCritical || !a.Verdict.Evasion || !strings.Contains(a.Summary, "pausing") {
		t.Fatalf("%+v", a)
	}
	if _, why := trustRule(a); why == "" {
		t.Fatal("evasion must never be trusted permanently")
	}
	// Even a program you trusted for this bait.
	e2, f2 := setup("balanced")
	signed(f2, code, "Microsoft Corporation")
	e2.cfg.Ignore = []config.IgnoreRule{{Path: code, Signer: "Microsoft", Baits: []string{"desktop-passwords"}}}
	e2.Configure(e2.cfg, stateWithAll())
	e2.HandleAccess(ev(300, code, desktopBait, 1))
	if len(f2.saved) != 0 {
		t.Fatal("trusted read should be silent")
	}
	e2.NoteEvasion(301, "ghost")
	e2.HandleAccess(ev(301, code, desktopBait, 1))
	if a := only(f2); a == nil || a.Tier != config.TierCritical {
		t.Fatalf("trusted, but evading: %+v", a)
	}
	// Not Defender, though.
	def := `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe`
	signed(f2, def, "Microsoft Corporation")
	e2.NoteEvasion(5, "ghost")
	before := len(f2.saved)
	e2.HandleAccess(ev(5, def, desktopBait, 1))
	if len(f2.saved) != before {
		t.Fatal("Defender is never escalated")
	}
}

// A hard link gives a bait a second name; reading it by that name used to
// produce an event ABA didn't recognise. The service now resolves it, and the
// engine treats the trick as what it is.
func TestReadThroughAHardLinkIsCritical(t *testing.T) {
	e, f := setup("balanced")
	tool := `C:\Program Files\Tool\tool.exe`
	signed(f, tool, "Tool Inc")
	x := ev(100, tool, desktopBait, 1)
	x.Alias = `C:\Users\bob\AppData\Local\Temp\cache.dat`
	e.HandleAccess(x)
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !strings.Contains(a.Summary, "hard link") {
		t.Fatalf("%+v", a)
	}
}

// Reading a file through an execute-only memory mapping never asks for read
// access. Windows logs that as "execute"; it's a read.
func TestExecuteAccessCountsAsARead(t *testing.T) {
	e, f := setup("balanced")
	e.HandleAccess(ev(100, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 0x20))
	if a := only(f); a == nil || a.Kind != alerts.KindRead || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) {
		t.Fatalf("%+v", a)
	}
}

// A running program can rename its own file and put a signed one in its
// place, so that "its" signature is someone else's.
func TestRenamedProgramIsJudgedByWhatRuns(t *testing.T) {
	e, f := setup("balanced")
	startedAs := `C:\Users\bob\AppData\Local\Temp\setup.exe`
	now := `C:\Users\bob\AppData\Local\Temp\setup.tmp`
	signed(f, startedAs, "Microsoft Corporation") // the signed file planted at the old path
	f.images[100] = now                           // what Windows says is really running
	e.HandleAccess(ev(100, startedAs, desktopBait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || a.Process.Image != now {
		t.Fatalf("%+v", a)
	}
	if len(f.blocked) != 1 || f.blocked[0] != now {
		t.Fatalf("the running file's internet must be cut, not the planted one's: %v", f.blocked)
	}
	if !strings.Contains(strings.Join(a.Verdict.Reasons, " "), "renamed") {
		t.Fatalf("reasons: %v", a.Verdict.Reasons)
	}
}

// DLL sideloading: a genuine signed program, started from a folder the
// attacker controls, loads the stealer as a DLL. It used to be "a signed
// program in a user folder": a warning, not frozen.
func TestSideloadedSignedProgramIsCritical(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\Downloads\Setup\VendorUpdater.exe`
	signed(f, img, "Vendor Inc")
	f.sideDLL[100] = `C:\Users\bob\Downloads\Setup\version.dll`
	e.HandleAccess(ev(100, img, desktopBait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !strings.Contains(a.Summary, "version.dll") {
		t.Fatalf("%+v", a)
	}
	// The same program without a stray DLL stays a warning.
	e2, f2 := setup("balanced")
	signed(f2, img, "Vendor Inc")
	e2.HandleAccess(ev(100, img, desktopBait, 1))
	if a := only(f2); a.Tier != config.TierWarn || len(f2.state.Frozen) != 0 {
		t.Fatalf("clean signed program: %+v", a)
	}
}

// "The real app read its own decoy" retires the decoy. The real app's name
// and signature used to be enough: copy the genuine Discord.exe anywhere, or
// put a DLL next to it, and ABA removed its own bait.
func TestOnlyTheInstalledAppRetiresItsDecoy(t *testing.T) {
	e, f := setup("balanced")
	elsewhere := `C:\Users\bob\Downloads\d\Discord.exe`
	signed(f, elsewhere, "Discord Inc.")
	e.HandleAccess(ev(100, elsewhere, discordBait, 1))
	if a := only(f); len(f.retired) != 0 || a == nil || a.Kind == alerts.KindDecoyRetired {
		t.Fatalf("a copy of the genuine app outside its install folder retired the decoy: %+v", a)
	}
	e2, f2 := setup("balanced")
	installed := `C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`
	signed(f2, installed, "Discord Inc.")
	f2.sideDLL[200] = `C:\Users\bob\AppData\Local\Discord\app-1.0.9172\dwmapi.dll`
	e2.HandleAccess(ev(200, installed, discordBait, 1))
	if a := only(f2); len(f2.retired) != 0 || a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) {
		t.Fatalf("the genuine app with an unsigned DLL in its folder: %+v retired=%v", a, f2.retired)
	}
	// The plain, installed, genuine app still does, and you hear about it.
	e3, f3 := setup("balanced")
	signed(f3, installed, "Discord Inc.")
	e3.HandleAccess(ev(300, installed, discordBait, 1))
	if a := only(f3); len(f3.retired) != 1 || a.Kind != alerts.KindDecoyRetired || a.Tier != config.TierWarn || len(f3.phone) != 1 {
		t.Fatalf("genuine install: %+v retired=%v phone=%v", a, f3.retired, f3.phone)
	}
}

// Sweep detection counted per process: use a new process (or a different
// Windows tool) for each app's data and none of them ever read three.
func TestSweepSplitOverSeveralProcesses(t *testing.T) {
	e, f := setup("balanced")
	tools := []string{`C:\Windows\System32\find.exe`, `C:\Windows\System32\notepad.exe`, `C:\Windows\System32\wermgr.exe`}
	for _, t := range tools {
		signed(f, t, "Microsoft Windows")
	}
	e.HandleAccess(ev(100, tools[0], desktopBait, 1))
	e.HandleAccess(ev(101, tools[1], discordBait, 1))
	for _, a := range f.saved {
		if a.Tier == config.TierCritical {
			t.Fatalf("two apps' data by two programs isn't a sweep yet: %+v", a)
		}
	}
	e.HandleAccess(ev(102, tools[2], chromeBait, 1))
	a := lastAlert(f)
	if a.Tier != config.TierCritical || len(a.Verdict.Swept) != 3 || !strings.Contains(a.Summary, "3 programs together") {
		t.Fatalf("third app by a third program: %+v", a)
	}
	// All three are stopped, not just the last one.
	for _, pid := range []uint32{100, 101, 102} {
		if !hasPID(f.suspended, pid) {
			t.Errorf("pid %d not frozen: %v", pid, f.suspended)
		}
	}
	if len(f.blocked) != 3 {
		t.Errorf("all three programs' internet should be cut: %v", f.blocked)
	}
	// Frozen mid-open as well.
	e2, f2 := setup("balanced")
	e2.cfg.InstantFreeze = true
	for i, tool := range tools {
		signed(f2, tool, "Microsoft Windows")
		f2.images[uint32(200+i)] = tool
	}
	if e2.DecideInstant(200, desktopBait) || e2.DecideInstant(201, discordBait) {
		t.Fatal("not a sweep yet")
	}
	if !e2.DecideInstant(202, chromeBait) {
		t.Fatal("the program completing a split-up sweep must be frozen as it opens the bait")
	}
}

// ...but programs you trusted for all baits, Defender, services and
// administrators' tools are never part of a "team".
func TestSplitSweepLeavesExemptProgramsOut(t *testing.T) {
	e, f := setup("balanced")
	bb := `C:\Program Files\Backblaze\bztransmit64.exe`
	signed(f, bb, "Backblaze, Inc.")
	e.cfg.Ignore = []config.IgnoreRule{{Path: bb, Signer: "Backblaze"}}
	e.Configure(e.cfg, stateWithAll())
	adm := `C:\Program Files\Tool\tool.exe`
	signed(f, adm, "Tool Inc")
	f.elevated[1001] = true
	np := `C:\Windows\System32\notepad.exe`
	signed(f, np, "Microsoft Windows")
	e.HandleAccess(ev(1000, bb, discordBait, 1))
	e.HandleAccess(ev(1001, adm, chromeBait, 1))
	e.HandleAccess(ev(1002, np, desktopBait, 1)) // you, opening your own file
	for _, a := range f.saved {
		if a.Tier == config.TierCritical {
			t.Fatalf("a backup tool, an admin tool and Notepad are not a team: %+v", a)
		}
	}
}

// Freezing only the process that touched the bait left the rest of the
// stealer running: the loader that started it, other copies of it.
func TestTheWholeStealerIsFrozen(t *testing.T) {
	e, f := setup("balanced")
	stealer := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	loader := `C:\Users\bob\AppData\Local\Temp\loader.exe`
	ps := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	explorer := `C:\Windows\explorer.exe`
	signed(f, ps, "Microsoft Windows")
	signed(f, explorer, "Microsoft Windows")
	f.parents[100] = []procinfo.Ancestor{{PID: 90, Image: loader}, {PID: 80, Image: ps}, {PID: 70, Image: explorer}, {PID: 60, Image: loader}}
	f.running[stealer] = []uint32{100, 110} // a second copy of it, not a child
	e.HandleAccess(ev(100, stealer, desktopBait, 1))
	a := only(f)
	for _, pid := range []uint32{100, 90, 80, 110} {
		if !hasPID(f.suspended, pid) {
			t.Errorf("pid %d should be frozen: %v", pid, f.suspended)
		}
	}
	if hasPID(f.suspended, 70) || hasPID(f.suspended, 60) {
		t.Fatalf("the chain stops at Explorer: %v", f.suspended)
	}
	if len(f.blocked) != 2 { // the stealer and its (unsigned) loader; not PowerShell
		t.Fatalf("blocked %v", f.blocked)
	}
	var onRecord []uint32
	for _, fr := range f.state.Frozen {
		onRecord = append(onRecord, fr.PID)
	}
	for _, pid := range []uint32{100, 90, 80, 110} {
		if !hasPID(onRecord, pid) || !hasPID(f.held, pid) {
			t.Errorf("pid %d must be on record and held (so `aba resume`/`kill` cover it): record=%v held=%v", pid, onRecord, f.held)
		}
	}
	if !strings.Contains(a.Actions[0].Detail, "loader.exe") {
		t.Fatalf("the alert should say what else was frozen: %q", a.Actions[0].Detail)
	}
	// A signed app's reader doesn't take its parents down with it.
	e2, f2 := setup("strict")
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	signed(f2, code, "Microsoft Corporation")
	signed(f2, ps, "Microsoft Windows")
	f2.parents[200] = []procinfo.Ancestor{{PID: 190, Image: ps}}
	e2.HandleAccess(ev(200, code, desktopBait, 1))
	if hasPID(f2.suspended, 190) {
		t.Fatal("only a critical reader's relatives are frozen")
	}
}

// What's frozen is held, so no other program running as you can resume it.
func TestFrozenProcessesAreHeld(t *testing.T) {
	e, f := setup("balanced")
	e.HandleAccess(ev(100, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 1))
	if len(f.held) != 2 || len(f.state.Frozen) != 2 {
		t.Fatalf("held %v, frozen %+v", f.held, f.state.Frozen)
	}
	// Not what was only paused while its signature was checked.
	e2, f2 := setup("balanced")
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	signed(f2, code, "Microsoft Corporation")
	e2.HandleAccess(ev(200, code, desktopBait, 1))
	if len(f2.held) != 0 {
		t.Fatalf("a program that was let go again must not be held: %v", f2.held)
	}
}

// A ghost opener that the instant path didn't freeze (alert-only setups)
// still gets its alert through the ordinary path.
func TestEvasionSurvivesIntoTheEventLogPath(t *testing.T) {
	e, f := setup("alert")
	np := `C:\Windows\System32\notepad.exe`
	signed(f, np, "Microsoft Windows")
	e.NoteEvasion(100, "it opened the bait in a way that keeps Windows from pausing it")
	e.HandleAccess(ev(100, np, desktopBait, 1))
	if a := only(f); a == nil || a.Tier != config.TierCritical || len(a.Actions) != 0 || len(f.phone) != 1 {
		t.Fatalf("%+v", a)
	}
}

// A backup or security tool that really opens files without waiting, or keeps
// hard-linked snapshots, would otherwise be critical on every run with no way
// to allow it. An administrator can: a rule made with --allow-tricks covers
// it. Nothing else does, and no rule covers a copy of ABA.
func TestAnAdminRuleCanAllowTricks(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	tool := `C:\Users\bob\AppData\Local\Programs\SyncTool\sync.exe`
	signed(f, tool, "Sync Tool GmbH")
	f.images[100] = tool
	e.cfg.Ignore = []config.IgnoreRule{{Path: tool, Signer: "Sync Tool", Tricks: true}}
	e.Configure(e.cfg, stateWithAll())

	e.NoteEvasion(100, "ghost")
	if e.DecideInstant(100, desktopBait) {
		t.Fatal("allowed by an admin rule: must not be frozen at the open")
	}
	e.HandleAccess(ev(100, tool, desktopBait, 1))
	x := ev(100, tool, discordBait, 1)
	x.Alias = `D:\snapshots\2026-01-01\000005.ldb`
	e.HandleAccess(x)
	// (Its publisher is checked after the first, split-second freeze, like any
	// program trusted by publisher: it's let go again at once.)
	if len(f.saved) != 0 || len(f.state.Frozen) != 0 || len(f.resumed) < len(f.suspended) {
		t.Fatalf("allowed by an admin rule: no alert, nothing left frozen: alerts=%d suspended=%v resumed=%v", len(f.saved), f.suspended, f.resumed)
	}

	// The same program under another publisher isn't that program.
	other := `C:\Users\bob\AppData\Local\Programs\SyncTool\sync2.exe`
	signed(f, other, "Somebody Else")
	e.cfg.Ignore = []config.IgnoreRule{{Path: other, Signer: "Sync Tool", Tricks: true}}
	e.Configure(e.cfg, stateWithAll())
	y := ev(101, other, desktopBait, 1)
	y.Alias = `C:\Users\bob\AppData\Local\Temp\cache.dat`
	e.HandleAccess(y)
	if a := only(f); a == nil || a.Tier != config.TierCritical || !a.Verdict.Evasion {
		t.Fatalf("wrong publisher, reading through a hard link: %+v", a)
	}
}

// trustRule mirrors what package trust decides for an alert, without
// importing it (it would be an import cycle in tests).
func trustRule(a *alerts.Alert) (config.IgnoreRule, string) {
	if a.Verdict.Evasion {
		return config.IgnoreRule{}, "evasion is never trusted"
	}
	return config.IgnoreRule{Path: a.Process.Image}, ""
}

// A rule that needs no signature (an unsigned program trusted by its
// fingerprint) is matched before the signature check. Evasion must still get
// through that shortcut.
func TestEvasionIsNotCoveredByAFingerprintRule(t *testing.T) {
	e, f := setup("balanced")
	tool := `C:\Users\bob\tools\mytool.exe`
	f.hashes[tool] = "abc123"
	e.cfg.Ignore = []config.IgnoreRule{{Path: tool, SHA256: "abc123", Baits: []string{"desktop-passwords"}}}
	e.Configure(e.cfg, stateWithAll())
	e.HandleAccess(ev(100, tool, desktopBait, 1))
	if len(f.saved) != 0 || len(f.suspended) != 0 {
		t.Fatalf("the trusted read should be silent: %+v", only(f))
	}
	x := ev(101, tool, desktopBait, 1)
	x.Alias = `C:\Users\bob\AppData\Local\Temp\cache.dat`
	e.HandleAccess(x)
	if a := only(f); a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) {
		t.Fatalf("trusted by fingerprint, but reading through a hard link: %+v", a)
	}
}
