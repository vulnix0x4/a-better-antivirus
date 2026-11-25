// Package engine turns bait access events into verdicts, responses and alerts.
//
// Order of operations for a new reader (speed matters: many stealers collect
// everything first and upload once at the end):
//
//  1. instant verdict from path/name alone, assuming the binary is unsigned
//  2. freeze immediately if that verdict's response includes freezing
//  3. verify the signature, compute the final verdict
//  4. unfreeze if the final verdict doesn't warrant it (e.g. a signed app)
//  5. collect forensics while the process is frozen
//  6. block / kill / isolate as configured, then alert
//
// The engine is the same on every operating system. It hears about bait
// accesses from the OS's watchers (see package detect for the two ways they
// report) and acts through Ops, which the service fills in with that OS's
// way of freezing, blocking and notifying.
package engine

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/origin"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Ops are the side effects the engine needs; the service provides real ones.
type Ops interface {
	ImagePath(pid uint32) (string, error)
	CreateTime(pid uint32) int64
	Verify(path string) provenance.Result
	SuspendTree(pid uint32) ([]uint32, error)
	Resume(pids []uint32)
	KillTree(pid uint32) error
	Forensics(pid uint32, p *alerts.Process)
	BlockProgram(path string) error
	Isolate() error
	DisableAdapters() ([]string, error)
	SaveAlert(a *alerts.Alert) error
	UpdateState(fn func(*config.State) error) error
	NotifyDesktop(a *alerts.Alert)
	NotifyPhone(a *alerts.Alert)
	RetireDecoy(baitID string, why string)
	PendingTest() *TestRequest
	UserSession(pid uint32) bool // runs in an interactive user session (not session 0)
	IsSelf(image string) bool    // the executable is ABA itself (same file hash as the service)
	Elevated(pid uint32) bool    // runs with an elevated (admin) token
	Hash(image string) string    // SHA-256 of a file (cached)
	CommandLine(pid uint32) string
	// InjectedCode looks inside a process for running code that isn't from any
	// file on disk (a stealer injected into a legitimate program).
	InjectedCode(pid uint32) (string, bool)
	// SideLoaded looks for an unsigned DLL loaded from the program's own folder
	// (a stealer riding inside a signed program) and returns its path.
	SideLoaded(pid uint32, image string) (string, bool)
	// Hold locks frozen processes so no other program can un-freeze them.
	Hold(pids []uint32)
	// Ancestors are the processes that started pid: parent first.
	Ancestors(pid uint32) []procinfo.Ancestor
	// SuspendMore freezes root and what it started, leaving out already.
	SuspendMore(root uint32, already []uint32) []uint32
	// RunningImage lists the processes running the executable at path.
	RunningImage(path string) []uint32
	ClearTest()
	Logf(format string, args ...any)
	// Autopsy looks into a caught program while it's frozen (see package
	// autopsy): what real data it opened, what it staged, where it was
	// sending. It takes a while, so the engine asks only once the alert is out.
	Autopsy(c autopsy.Case) *alerts.Autopsy
	// NotifyAutopsy tells the person what the autopsy found, when it found
	// that the program read real data.
	NotifyAutopsy(a *alerts.Alert)
	// Browser gathers the facts about the browser instance pid (running
	// image) belongs to: see procinfo.Browser. procinfo.ErrGone when it has
	// exited, procinfo.ErrUnsupported where the system doesn't say.
	Browser(pid uint32, image string) (*procinfo.BrowserInstance, error)
	// VisibleWindow reports whether any of pids has a window on the screen of
	// the person using it. known is false when that couldn't be found out
	// (which never means "hidden").
	VisibleWindow(pids []uint32) (visible, known bool)
}

// TestRequest marks a reader process started by `aba test`.
type TestRequest struct {
	PID   uint32    `json:"pid"`
	Nonce string    `json:"nonce"`
	Since time.Time `json:"since"`
	// Clipboard: `aba clipboard test`. The reader is a fake clipper, and the
	// clipboard guards put a bait out now instead of waiting for a quiet moment.
	Clipboard bool `json:"clipboard,omitempty"`
}

// Engine is safe for concurrent use.
type Engine struct {
	Ops     Ops
	SelfPID uint32

	mu          sync.Mutex
	cfg         *config.Config
	classifier  *classify.Classifier
	index       map[string]string // lower path -> bait id
	baitNames   map[string]string
	incidents   map[uint32]*incident
	claimed     map[uint32]time.Time        // PIDs the instant path is handling
	seen        map[string]time.Time        // program|bait -> last notification, for alerts with no action
	touched     map[uint32]*sweep           // baits each process opened recently
	wrecked     map[uint32]*sweep           // folders each process rewrote document baits in recently
	sids        map[uint32]string           // account a process read baits as (detect.Access.UserID), as the watcher reported it
	pending     map[uint32]chan struct{}    // instant decisions in progress
	later       map[uint32][]alerts.BaitHit // what a program caught in its open went on to do, until its alert is on record
	eventFrozen map[uint32]time.Time        // processes the event-log path froze
	marks       map[uint32]mark             // processes seen using a trick to dodge detection
	team        []teamRead                  // recent bait reads by anyone, for sweeps split over several processes

	hosts     map[uint32]hostSeen  // browser facts gathered per opener, before anything was frozen (see host.go)
	hostLocks map[string]*hostLock // one decision at a time per browser instance
	roots     map[uint32][]uint32  // what the instant path is to freeze for an opener it decided on (see InstantRoots)
	adoptWait time.Duration        // how long to give a browser that may be taking a fake profile as its own (see host.go)
	takeWait  time.Duration        // the same, when it went to delete or overwrite the fake's files
}

// mark notes that a process did something only evasion explains.
type mark struct {
	why        string
	createTime int64
	at         time.Time
}

// teamRead is one program reading one app's bait.
type teamRead struct {
	pid        uint32
	createTime int64
	unit       string
	image      string
	at         time.Time
}

// sweep is what one process has opened lately. Stealers grab everything they
// know (browsers, Discord, wallets…) in seconds; a real app only ever touches
// its own data. So a process that reads several different apps' baits is a
// stealer, whatever it is or claims to be: a trusted app with code injected
// into it, a signed program, a Windows component.
type sweep struct {
	createTime int64
	baits      map[string]time.Time
}

// sweepApps distinct baits within window make a sweep.
const sweepApps = 3

type incident struct {
	alert      *alerts.Alert
	createTime int64
	last       time.Time
	// wrecked: it had already gone to overwrite documents in several
	// folders when this alert was made, so that's been judged.
	wrecked bool
	// quiet: the alert was noted quietly (see quietly); if what the program
	// goes on to do changes that, you're told then.
	quiet bool
}

// quietly reports whether alert a (verdict v) is only noted, with no popup
// and no phone alert: a read by a program ABA rates as looking legitimate
// (info), about which nothing was done. Never a test, a decoy being retired,
// a browser going through its fake profile, a sweep, or a trick; and never
// anything that read, wrote or deleted more than that. It's still saved, in
// the history and counted by the sweep rules, but waits for no answer.
func quietly(a *alerts.Alert, v classify.Verdict) bool {
	return !a.Test && a.Kind == alerts.KindRead && v.Tier == config.TierInfo && len(a.Actions) == 0 &&
		!v.DecoyOwner && !v.Host && !v.Evasion && len(v.Swept) == 0 && !v.Ignored
}

// tell notifies you about a (desktop, and phone from your minimum tier on).
func (e *Engine) tell(a *alerts.Alert) {
	e.Ops.NotifyDesktop(a)
	e.mu.Lock()
	min := config.TierWarn
	if e.cfg != nil {
		min = e.cfg.PhoneMinTier
	}
	e.mu.Unlock()
	if a.Test || a.Tier.Rank() >= min.Rank() {
		e.Ops.NotifyPhone(a)
	}
}

// aggregation window: further bait hits by the same process join one alert.
const window = 2 * time.Minute

func New(ops Ops, selfPID uint32) *Engine {
	return &Engine{Ops: ops, SelfPID: selfPID, incidents: map[uint32]*incident{}, claimed: map[uint32]time.Time{},
		seen: map[string]time.Time{}, touched: map[uint32]*sweep{}, wrecked: map[uint32]*sweep{}, sids: map[uint32]string{},
		pending: map[uint32]chan struct{}{}, later: map[uint32][]alerts.BaitHit{}, eventFrozen: map[uint32]time.Time{}, marks: map[uint32]mark{},
		hosts: map[uint32]hostSeen{}, hostLocks: map[string]*hostLock{}, roots: map[uint32][]uint32{}, adoptWait: adoptWait, takeWait: takeWait}
}

// Configure (re)loads config and the bait index.
func (e *Engine) Configure(cfg *config.Config, st *config.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	e.classifier = &classify.Classifier{Env: classify.DefaultEnv(), Ignore: cfg.Ignore,
		Hash: e.Ops.Hash, CommandLine: e.Ops.CommandLine, UserSession: e.userSession}
	e.index = baits.Index(st)
	e.baitNames = map[string]string{}
	for id, b := range st.Baits {
		e.baitNames[id] = b.Name
	}
}

// IsBait reports whether path is a watched bait file.
func (e *Engine) IsBait(path string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.index[paths.Key(path)]
	return id, ok
}

// touchable: ABA never suspends or kills itself or the Windows processes that
// would take the desktop down with them (see classify.ProtectedProcess, which
// goes by the real file, not by the name).
func (e *Engine) touchable(pid uint32, image string) bool {
	if pid == 0 || pid == 4 || pid == e.SelfPID {
		return false
	}
	e.mu.Lock()
	cls := e.classifier
	e.mu.Unlock()
	return cls == nil || !cls.ProtectedProcess(image)
}

// NoteEvasion records that pid did something only an attempt to dodge
// detection explains (e.g. opened a bait in a way that avoids being paused).
// Whatever it is or is signed by, its bait reads are critical from then on.
func (e *Engine) NoteEvasion(pid uint32, why string) {
	ct := e.Ops.CreateTime(pid)
	e.mu.Lock()
	for p, m := range e.marks {
		if time.Since(m.at) > markFor {
			delete(e.marks, p)
		}
	}
	e.marks[pid] = mark{why: why, createTime: ct, at: time.Now()}
	e.mu.Unlock()
}

// markFor is how long an evasion mark sticks to a process.
const markFor = 30 * time.Minute

func (e *Engine) evasion(pid uint32) string {
	e.mu.Lock()
	m, ok := e.marks[pid]
	e.mu.Unlock()
	if !ok || time.Since(m.at) > markFor {
		return ""
	}
	if ct := e.Ops.CreateTime(pid); ct != 0 && m.createTime != 0 && ct != m.createTime {
		return "" // the PID was reused by another process
	}
	return m.why
}

// ownCopy: the reader is a copy of ABA's own program. Running as
// administrator that's ABA's own tooling. Not elevated, it's something else
// using ABA's program as a disguise (started it and injected code into it):
// nothing in ABA reads a bait without admin rights.
func (e *Engine) ownCopy(pid uint32, image string) (self, disguise bool) {
	if !e.Ops.IsSelf(image) {
		return false, false
	}
	if e.Ops.CreateTime(pid) != 0 && e.Ops.Elevated(pid) {
		return true, false
	}
	return false, true
}

// evasive turns v into a critical verdict because of why.
func evasive(v classify.Verdict, why string) classify.Verdict {
	return classify.Verdict{Tier: config.TierCritical, Evasion: true, Swept: v.Swept, Reasons: append([]string{why}, v.Reasons...)}
}

// DecideInstant runs while a bait opener is paused inside Windows (see package
// instant). It reports whether pid should be frozen right now, before it can
// read. It's deliberately conservative: only ordinary programs in a user
// session whose verdict calls for freezing. Everything else is let through
// and handled by the normal audit-log path if it actually reads.
func (e *Engine) DecideInstant(pid uint32, path string) bool {
	ok, _ := e.DecideInstantWhy(pid, path)
	return ok
}

// DecideInstantWhy is DecideInstant plus the reason, for the service log.
func (e *Engine) DecideInstantWhy(pid uint32, path string) (bool, string) {
	return e.DecideInstantOpWhy(pid, path, detect.OpRead)
}

// DecideInstantOpWhy is DecideInstantWhy for a watcher that knows what the
// open asked for: to read the bait, only to change it (OpWrite) or only to
// delete it (OpDelete).
func (e *Engine) DecideInstantOpWhy(pid uint32, path string, op detect.Op) (bool, string) {
	e.mu.Lock()
	cfg, cls := e.cfg, e.classifier
	baitID, isBait := e.index[paths.Key(path)]
	e.mu.Unlock()
	if cfg == nil || !isBait || pid == e.SelfPID {
		return false, "not a bait / ABA itself"
	}
	image, err := e.Ops.ImagePath(pid)
	if err != nil || image == "" {
		return false, "can't see its executable"
	}
	if !e.touchable(pid, image) {
		return false, image + " is a protected system process"
	}
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == pid {
		e.claim(pid)
		return true, image + " is the `aba test` reader"
	}
	if !cfg.InstantFreeze {
		return false, "instant freeze is off"
	}
	// From here on this pid is being decided: the event-log path waits for
	// the decision instead of freezing it too (hashing and the signature check
	// below can take longer than Windows takes to log the read).
	done := e.beginDecision(pid)
	if done == nil {
		return false, image + " is already being handled (another bait or the event log got there first)"
	}
	// Instant freeze acts on a split-second inference, so it only touches
	// ordinary, non-elevated programs in a user session. Admin tools that inspect
	// baits (and elevated malware, out of scope) go through the event-log path.
	if !e.Ops.UserSession(pid) {
		done(false)
		return false, image + " runs in session 0 (system/service)"
	}
	if e.Ops.Elevated(pid) {
		done(false)
		return false, image + asAdmin
	}
	sig := e.Ops.Verify(image)
	v := cls.Final(image, pid, e.baitRef(baitID), sig)
	exempt := cls.SweepExempt(image, pid, &sig)
	// Deleting several apps' data isn't going through it: uninstallers and
	// cleaners do that. Reading or rewriting it is.
	// (Never the genuine browser going through its fake profile: see host.go,
	// and hostRead.)
	if op != detect.OpDelete && !v.Host {
		if swept := e.touch(pid, baitID, time.Now()); len(swept) >= sweepApps && !exempt {
			v = e.sweepVerdict(v, swept)
		}
	}
	// Going to overwrite your documents in a second folder: held here, in
	// the open, whatever it is (see wreck).
	if op == detect.OpWrite && !exempt && !classify.OSVendorSigned(sig) {
		if wrecked := e.wreck(pid, baitID, path, time.Now()); len(wrecked) >= wreckFolders {
			v = e.wreckVerdict(v, wrecked, "write")
		}
	}
	if !v.Builtin && !v.DecoyOwner {
		// (Elevated copies of ABA were let through above.)
		if _, disguise := e.ownCopy(pid, image); disguise {
			v = evasive(v, disguiseWhy)
		} else if why := e.evasion(pid); why != "" && !cls.TricksAllowed(image, pid, baitID, &sig) {
			v = evasive(v, why)
		}
	}
	if v.Host {
		// The genuine browser going through a fake profile: frozen here only
		// when the quick facts show it isn't the browser you're using (see
		// host.go). Everything else waits for the event log, which can look
		// at its windows first.
		p := e.hostPlanFor(cls, pid, image, false)
		switch {
		case p.unsupported:
		case p.gone:
			done(false)
			return false, image + " (a browser going through a fake profile) has already exited"
		case !p.stop:
			done(false)
			return false, image + " went through a fake profile, but may be the browser you're using: left to the event log, which checks its windows"
		default:
			if !config.Has(cfg.ActionsFor(config.TierCritical, time.Now()), config.ActionFreeze) {
				done(false)
				return false, image + " is a browser started by a stealer, but critical readers aren't frozen right now"
			}
			roots := []uint32{p.inst.Main}
			if e.starterFreezable(cls, p, p.inst.Starter, p.inst.StarterImage) {
				roots = append(roots, p.inst.Starter)
			}
			e.setRoots(pid, roots)
			done(true)
			return true, fmt.Sprintf("%s is a browser that isn't the one you're using (%s): freezing it from its main process %d, with %v", image, p.stopVerdict(v).Reasons[0], p.inst.Main, roots[1:])
		}
	}
	if v.Ignored || v.DecoyOwner {
		done(false)
		return false, image + " is ignored or the real app"
	}
	if !exempt && v.Tier != config.TierCritical && op == detect.OpRead {
		if units, _ := e.joinTeam(pid, baitID, image, time.Now()); units != nil {
			v = e.teamVerdict(v, units, 0)
		}
	}
	if op == detect.OpDelete && (v.Tier != config.TierCritical || classify.ScriptHost(image)) {
		// A program that looks legitimate removing a file, or a script host
		// removing one: reported (the event log names it), not frozen here.
		// See actionsFor in handle, which also counts a script's deletes.
		done(false)
		return false, fmt.Sprintf("%s is %s; deleting a bait isn't stopped inside the open for it", image, v.Tier)
	}
	if !config.Has(cfg.ActionsFor(v.Tier, time.Now()), config.ActionFreeze) {
		done(false)
		return false, fmt.Sprintf("%s is %s; that tier doesn't freeze right now", image, v.Tier)
	}
	done(true)
	return true, fmt.Sprintf("%s is %s", image, v.Tier)
}

// claimDedupe: several bait guards can fire in the same instant (e.g. while
// the service re-arms them) and all point at the same opener. Only the first
// may freeze it: Windows stacks suspensions, so a second freeze would leave it
// suspended after the user unfreezes it once.
const claimDedupe = 2 * time.Second

// beginDecision starts an instant decision about pid, or returns nil if pid
// is already being decided, was just claimed, or was frozen by the event-log
// path. The returned func ends the decision; claimed=true claims pid.
//
// Exactly one of the two paths may freeze a process: Windows stacks
// suspensions, so a double freeze leaves it suspended after one unfreeze.
func (e *Engine) beginDecision(pid uint32) func(claimed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending[pid] != nil {
		return nil
	}
	if t, ok := e.claimed[pid]; ok && time.Since(t) < claimDedupe {
		return nil
	}
	if t, ok := e.eventFrozen[pid]; ok && time.Since(t) < window {
		return nil
	}
	ch := make(chan struct{})
	e.pending[pid] = ch
	return func(claimed bool) {
		e.mu.Lock()
		if claimed {
			e.claimed[pid] = time.Now()
		}
		if e.pending[pid] == ch {
			delete(e.pending, pid)
		}
		e.mu.Unlock()
		close(ch)
	}
}

// waitDecision waits (briefly) for an instant decision about pid in progress.
func (e *Engine) waitDecision(pid uint32) {
	e.mu.Lock()
	ch := e.pending[pid]
	e.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
		}
	}
}

// ownFreeze is the event-log path asking to freeze pid itself: false if the
// instant path is deciding about it or has claimed it.
func (e *Engine) ownFreeze(pid uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending[pid] != nil {
		return false
	}
	if t, ok := e.claimed[pid]; ok && time.Since(t) < window {
		return false
	}
	for p, t := range e.eventFrozen {
		if time.Since(t) > window {
			delete(e.eventFrozen, p)
		}
	}
	e.eventFrozen[pid] = time.Now()
	return true
}

// claim marks pid as handled by the instant path, so the event-log path (which
// fires a moment later for the same read) doesn't freeze it a second time:
// Windows stacks suspensions, so a double freeze would need two unfreezes.
func (e *Engine) claim(pid uint32) {
	e.mu.Lock()
	now := time.Now()
	for p, t := range e.claimed {
		if now.Sub(t) > window {
			delete(e.claimed, p) // expired claims
		}
	}
	e.claimed[pid] = now
	e.mu.Unlock()
}

// Unclaim releases a claim (e.g. the instant freeze itself failed).
func (e *Engine) Unclaim(pid uint32) {
	e.mu.Lock()
	delete(e.claimed, pid)
	e.mu.Unlock()
}

// HandleOpen raises the alert (and runs the remaining responses) for a reader
// that DecideInstant froze mid-open. frozen is what was suspended.
func (e *Engine) HandleOpen(pid uint32, path string, at time.Time, frozen []uint32) {
	e.HandleOpenOp(pid, path, detect.OpRead, at, frozen)
}

// HandleOpenOp is HandleOpen for a watcher that knows what the open asked
// for: to read the bait, only to change it (OpWrite) or only to delete it.
func (e *Engine) HandleOpenOp(pid uint32, path string, op detect.Op, at time.Time, frozen []uint32) {
	e.handle(&detect.Access{PID: pid, Path: path, Op: op, Time: at}, frozen)
}

func (e *Engine) baitRef(id string) classify.Bait {
	b := classify.Bait{ID: id}
	if s, ok := baits.ByID(id); ok {
		b.OwnerExes, b.OwnerSigner, b.SharedSDK = s.OwnerExes, s.Signer, s.SharedSDK
		e.mu.Lock()
		cfg := e.cfg
		e.mu.Unlock()
		if cfg != nil {
			b.OwnerDirs = baits.OwnerDirs(s, cfg.User)
			b.Unadopted = s.Inside != nil && !baits.Adopted(s, cfg.User)
		}
	}
	return b
}

// HandleAccess processes one bait access that a watcher reports after the
// fact (on Windows, a Security 4663 event): the program isn't held.
func (e *Engine) HandleAccess(oa *detect.Access) { e.handle(oa, nil) }

// handle processes a bait access. preFrozen is non-nil when the reader was
// already frozen by the instant path, the moment it opened the bait.
func (e *Engine) handle(oa *detect.Access, preFrozen []uint32) {
	instant := preFrozen != nil
	claimedNow := func() bool {
		e.mu.Lock()
		t, ok := e.claimed[oa.PID]
		e.mu.Unlock()
		return ok && time.Since(t) < window
	}
	// tryFreeze: the event-log path may freeze only what the instant path
	// isn't freezing (a decision in progress is waited for).
	tryFreeze := func() bool {
		if e.ownFreeze(oa.PID) {
			return true
		}
		e.waitDecision(oa.PID)
		return e.ownFreeze(oa.PID)
	}
	if !instant {
		e.waitDecision(oa.PID)
		if claimedNow() {
			e.mu.Lock()
			inc := e.incidents[oa.PID]
			e.mu.Unlock()
			if inc != nil && !oldNews(oa.Time, inc.alert) && e.undone(inc.alert) {
				// Caught, then resumed by you: this is something new it did.
				// (Not when it did it before it was caught and the word only
				// comes now: that's the same case.)
				e.Unclaim(oa.PID)
				e.closeIncident(inc.alert)
			} else {
				// The instant path already caught and is reporting this process.
				// What it went on to do to the bait still belongs in that alert.
				e.noteAfter(oa)
				return
			}
		}
	}
	received := time.Now()
	baitID, ok := e.IsBait(oa.Path)
	if oa.Op == detect.OpSwap && oa.Swap != nil {
		baitID, ok = ClipboardBait, true
	}
	if !ok || oa.PID == e.SelfPID {
		return
	}
	access := "read"
	switch oa.Op {
	case detect.OpRead:
	case detect.OpDelete:
		access = "delete"
	case detect.OpWrite:
		access = "write"
	case detect.OpSwap:
		access = "swap"
	default:
		return
	}

	if oa.UserID != "" {
		e.mu.Lock()
		if len(e.sids) > 4096 {
			e.sids = map[uint32]string{}
		}
		e.sids[oa.PID] = oa.UserID
		e.mu.Unlock()
	}
	var swept []string
	hostOpen := e.hostRead(oa, baitID)
	if (access == "read" || access == "write") && !hostOpen {
		swept = e.touch(oa.PID, baitID, time.Now())
		if len(swept) >= sweepApps && !e.sweepable(oa.PID) {
			swept = nil
		}
	}
	// Rewriting your documents in folder after folder: ransomware, or a wiper.
	// So is a script deleting them in folder after folder. (A script host
	// deleting one bait is you, at a prompt or in a script of your own; an
	// ordinary program's deletes aren't counted at all, see wreck.)
	scripted := false
	if access == "delete" {
		img := oa.Image
		if live, err := e.Ops.ImagePath(oa.PID); err == nil && live != "" {
			img = live
		}
		scripted = classify.ScriptHost(img)
	}
	var wrecked []string
	if access == "write" || scripted {
		wrecked = e.wreck(oa.PID, baitID, oa.Path, time.Now())
		if len(wrecked) >= wreckFolders && !e.sweepable(oa.PID) {
			wrecked = nil
		}
	}

	// An earlier alert about it whose response has been undone since (you
	// resumed it, gave it its internet back, released it) is a closed case:
	// what it does now is a new alert, not a line in that one.
	e.mu.Lock()
	inc0 := e.incidents[oa.PID]
	e.mu.Unlock()
	if inc0 != nil && !instant && !oldNews(oa.Time, inc0.alert) && e.undone(inc0.alert) {
		e.closeIncident(inc0.alert)
	}

	e.mu.Lock()
	cfg, cls, name := e.cfg, e.classifier, e.baitNames[baitID]
	hit := alerts.BaitHit{ID: baitID, Name: name, Path: oa.Path, Access: access, Time: oa.Time}
	if access == "swap" {
		hit.Name, hit.Path = clipboardBaitName, "the clipboard"
	}
	if inc := e.incidents[oa.PID]; !instant && inc != nil && len(swept) >= sweepApps && (inc.alert.Tier != config.TierCritical || inc.alert.Verdict.KeepRunning) {
		// It started out looking harmless (or as the browser you're using,
		// left running) and has now read several apps' data: handle it again
		// as a sweep, with the full response.
		delete(e.incidents, oa.PID)
	}
	if inc := e.incidents[oa.PID]; !instant && inc != nil && len(wrecked) >= wreckFolders && !inc.wrecked &&
		(inc.alert.Tier != config.TierCritical || !inc.alert.Did(config.ActionFreeze)) {
		// Same: now it's rewriting folder after folder. (Judged once: a
		// program that's exempt, like OneDrive, isn't alerted about anew for
		// every file after that. A script host's first delete made a critical
		// alert that did nothing: that one is handled again too.)
		delete(e.incidents, oa.PID)
	}
	if inc := e.incidents[oa.PID]; access == "swap" && inc != nil && inc.alert.Tier != config.TierCritical {
		delete(e.incidents, oa.PID) // same: now it's a caught clipper
	}
	if inc := e.incidents[oa.PID]; !instant && inc != nil && ((inc.quiet && access != "read") || (inc.alert.Tier != config.TierCritical && hostOpen && !inc.alert.Verdict.Host)) {
		// Same: noted quietly as a read, and now it goes to change or delete
		// a bait; or now it's the genuine browser going through its fake
		// profile, which the host policy judges (see host.go). Neither is a
		// line to add to a quiet or harmless-looking alert.
		delete(e.incidents, oa.PID)
	}
	// Aggregate repeat hits into the open alert, except for instant catches: a
	// new freeze always gets its own alert and its own record in state (the
	// earlier alert may already be resolved, e.g. the user resumed the process).
	if inc := e.incidents[oa.PID]; !instant && inc != nil && time.Since(inc.last) < window &&
		(inc.createTime == 0 || inc.createTime == e.Ops.CreateTime(oa.PID)) {
		inc.last = time.Now()
		a := inc.alert
		dup := false
		for _, h := range a.Baits {
			dup = dup || (strings.EqualFold(h.Path, hit.Path) && h.Access == hit.Access)
		}
		if !dup {
			a.Baits = append(a.Baits, hit)
			cp := *a // the autopsy may be filling the alert in meanwhile (see autopsy)
			cp.Baits = append([]alerts.BaitHit(nil), a.Baits...)
			e.mu.Unlock()
			e.Ops.SaveAlert(&cp)
			return
		}
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	now := time.Now()
	// The event names the file the program was started from. A running
	// program can rename its own file and put something else (signed, innocent)
	// at the old path, so that checking "its" signature checks the wrong file.
	// While it's alive, Windows says which file is really running: go by that.
	image, startedAs := oa.Image, ""
	if live, err := e.Ops.ImagePath(oa.PID); err == nil && live != "" {
		if strings.Contains(image, `\`) && !paths.Same(paths.Long(live), paths.Long(image)) {
			startedAs = image
		}
		image = live
	}
	test := false
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == oa.PID {
		test = true
	}
	disguise := false
	if !test {
		self, d := e.ownCopy(oa.PID, image)
		if self {
			return // ABA's own tooling, running as administrator (doctor, bait adoption…)
		}
		disguise = d
	}
	createTime := e.Ops.CreateTime(oa.PID)
	ref := e.baitRef(baitID)
	learning := cfg.Learning(now) && !test
	actionsFor := func(t config.Tier) []config.Action {
		if test {
			return []config.Action{config.ActionFreeze} // a test never cuts the network
		}
		if access == "delete" && (t != config.TierCritical || (scripted && len(wrecked) < wreckFolders)) {
			// A program that looks legitimate removing a file (you, in
			// Explorer; a cleaner; a sync client moving your folders), or a
			// script host removing one (you again, at a prompt): the bait is
			// put back and you're told. A program that would be stopped for
			// reading a bait is stopped for destroying it too: that's a wiper,
			// or ransomware that deletes what it has encrypted a copy of.
			return nil
		}
		return cfg.ActionsFor(t, now)
	}

	isSweep := len(swept) >= sweepApps
	isWreck := len(wrecked) >= wreckFolders

	// 1-2. Instant verdict, freeze first.
	pre := cls.Prelim(image, oa.PID, ref)
	if isSweep && !cls.SweepExempt(image, oa.PID, nil) {
		pre = e.sweepVerdict(pre, swept)
	}
	if access == "swap" {
		pre = swapVerdict(oa.Swap) // whatever it is: nothing legitimate does that
	}
	// One of your rules covers it: done, unless it used a trick to dodge
	// detection (decided further down). Only a rule an administrator made for
	// exactly that covers a trick (`aba ignore add --allow-tricks`), and none
	// covers a copy of ABA.
	tricky := oa.Alias != "" || e.evasion(oa.PID) != ""
	tricksOK := false
	if tricky && !disguise && image != "" && cls.HasTricksRule() {
		s := e.Ops.Verify(image)
		tricksOK = cls.TricksAllowed(image, oa.PID, baitID, &s)
	}
	evading := disguise || (tricky && !tricksOK)
	// (Nor if it's rewriting folder after folder: that's judged below, once
	// its signature is known, whatever rule covers it.)
	if pre.Ignored && !instant && (pre.Builtin || (!evading && !isWreck)) {
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.Path, image, strings.Join(pre.Reasons, "; "))
		return
	}
	if evading && !pre.Builtin && pre.Tier != config.TierCritical {
		pre = classify.Verdict{Tier: config.TierCritical, Reasons: pre.Reasons} // freeze first, like any critical reader
	}
	frozen := preFrozen
	var latency time.Duration
	canTouch := e.touchable(oa.PID, image)
	// What looks like the genuine browser going through a fake profile isn't
	// frozen before its signature is known: a browser installed in your own
	// folders looks like any unsigned program there until then, and if it's
	// the one you're using, it's never frozen at all (see host.go).
	ownerWait := ref.Unadopted && !isSweep && !evading && access != "swap" && cls.OwnerCandidate(image, ref)
	if instant {
		latency = time.Since(oa.Time)
	} else if canTouch && !ownerWait && config.Has(actionsFor(pre.Tier), config.ActionFreeze) {
		if !tryFreeze() {
			if claimedNow() {
				return // the instant path froze it and reports it
			}
		} else {
			frozen, _ = e.Ops.SuspendTree(oa.PID)
			latency = time.Since(oa.Time)
		}
	}

	// 3-4. Signature and final verdict.
	sig := provenance.Result{}
	if image != "" {
		sig = e.Ops.Verify(image)
	}
	v := cls.Final(image, oa.PID, ref, sig)
	if isSweep && !cls.SweepExempt(image, oa.PID, &sig) {
		v = e.sweepVerdict(v, swept)
	}
	// Decided only now that the signature is known, and never for the
	// system's own programs: OneDrive and iCloud put your Desktop and
	// Documents back file by file, which looks the same from here.
	// (A script host's signature says nothing about the script: Windows'
	// own PowerShell deleting folder after folder is judged like any other.)
	if isWreck && !cls.SweepExempt(image, oa.PID, &sig) && (scripted || !classify.OSVendorSigned(sig)) {
		v = e.wreckVerdict(v, wrecked, access)
	}
	if access == "swap" {
		v = swapVerdict(oa.Swap)
	}
	// A Windows program reading app data is how injected stealers look: check
	// whether it's running code that isn't from any file on disk. (Trust rules
	// don't skip this; Defender and Windows Search do.)
	if !test && !v.Builtin && !v.DecoyOwner && v.Tier != config.TierCritical && access == "read" &&
		cls.SystemBinary(image) && e.Ops.UserSession(oa.PID) && !e.Ops.Elevated(oa.PID) {
		if detail, found := e.Ops.InjectedCode(oa.PID); found {
			v = classify.Verdict{Tier: config.TierCritical,
				Reasons: append([]string{filepath.Base(image) + " is part of " + platform.OSName() + ", but " + detail}, v.Reasons...)}
		}
	}
	// Tricks that only evasion explains make it critical whatever it is, trusted
	// from an alert or not. (Never Defender or Windows Search.)
	if !test && !v.Builtin && access == "read" {
		switch why := e.evasion(oa.PID); {
		case disguise:
			v = evasive(v, disguiseWhy)
		case tricksOK || (image != "" && cls.TricksAllowed(image, oa.PID, baitID, &sig)):
			// an administrator allowed this program to read baits that way
		case oa.Alias != "":
			v = evasive(v, "it read this through a second name it gave the file ("+oa.Alias+", a hard link): a trick to read a file without appearing to")
		case why != "":
			v = evasive(v, why)
		}
		// A signed program in a folder anyone can write to, running an unsigned
		// DLL from that same folder: the stealer is the DLL (sideloading). That
		// also means it isn't "the real app reading its own data".
		if !v.Evasion && !v.ByRule && sig.Valid && cls.UserWritable(image) && (v.DecoyOwner || (!v.Ignored && v.Tier != config.TierCritical)) {
			if dll, found := e.Ops.SideLoaded(oa.PID, image); found {
				v = classify.Verdict{Tier: config.TierCritical, Swept: v.Swept, Reasons: append([]string{
					filepath.Base(image) + " is signed, but it's running an unsigned DLL from its own folder (" + filepath.Base(dll) + "): that's how stealers ride inside legitimate programs", "the DLL: " + dll}, v.Reasons...)}
			}
		}
	}
	if v.Ignored {
		e.Ops.Resume(frozen)
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.Path, image, strings.Join(v.Reasons, "; "))
		return
	}
	// A sweep split over several programs, each reading too little to look
	// like one: together they went through several apps' data.
	// (Not the genuine browser going through its fake profile: that's settled
	// by the host policy, about that browser alone. A stealer's copy of it is
	// frozen with what started it, a closed case; the browser you use is cut
	// off. Either way, its read mustn't make a stranger that reads a bait
	// later on the "last member" of a team it has nothing to do with.)
	var teammates []teamRead
	if !test && access == "read" && !v.DecoyOwner && !v.Builtin && !v.Host && e.sweepable(oa.PID) && !cls.SweepExempt(image, oa.PID, &sig) {
		if units, members := e.joinTeam(oa.PID, baitID, image, now); units != nil && len(v.Swept) < sweepApps {
			v = e.teamVerdict(v, units, len(members))
			for _, m := range members {
				if m.pid != oa.PID {
					teammates = append(teammates, m)
				}
			}
		}
	}
	// The genuine browser went through a fake profile: which browser is it?
	// (See host.go.) Its other processes' reads join the one alert.
	var host *hostPlan
	var hostInst *procinfo.BrowserInstance // the browser instance, whatever came of it
	if v.Host && !test {
		inst, err := e.hostFacts(oa.PID, image)
		if inst != nil && err == nil {
			hostInst = inst
			unlock := e.lockHost(inst)
			defer unlock()
			if !instant && e.joinHost(inst, oa.PID, hit) {
				e.Ops.Resume(frozen)
				e.Ops.Logf("%s of %s by %s (pid %d) joins the alert about its browser", access, oa.Path, image, oa.PID)
				return
			}
		}
		if p := e.hostPlanFor(cls, oa.PID, image, !instant); !p.unsupported {
			host = &p
		}
	}
	if host != nil {
		switch {
		case host.gone:
			v = goneVerdict(v, image)
		case host.stop:
			v = host.stopVerdict(v)
		case e.stillUnadopted(baitID, access == "delete" || access == "write"):
			v = host.keepVerdict(v)
		default:
			// It took the folder as a profile of its own meanwhile (you added
			// one): the genuine app at work on its own data.
			v = e.tookVerdict(image, baitID)
			host = nil
		}
	}
	if v.DecoyOwner && !v.Host && embedded(baitID) {
		v = e.tookVerdict(image, baitID) // listed as its own before ABA even looked
	}
	if startedAs != "" {
		v.Reasons = append(v.Reasons, "its file was renamed after it started (it was started as "+startedAs+")")
	}
	acts := actionsFor(v.Tier)
	if v.DecoyOwner {
		acts = nil
	}
	// The browser you're using is never frozen or killed; one that has
	// exited can't be, and cutting its program's internet would only cut
	// your own windows.
	wouldStop, goneFreeze := false, false
	if host != nil && v.KeepRunning {
		wouldStop = config.Has(acts, config.ActionFreeze) || config.Has(acts, config.ActionKill)
		acts = without(acts, config.ActionFreeze, config.ActionKill)
	}
	if host != nil && host.gone {
		goneFreeze = config.Has(acts, config.ActionFreeze)
		acts = without(acts, config.ActionFreeze, config.ActionKill, config.ActionBlockProgram)
	}
	// A browser that isn't the one you're using is frozen from its main
	// process: all of it, whichever of its processes opened the bait.
	freezeRoot := oa.PID
	stopHost := host != nil && host.stop
	if stopHost {
		freezeRoot = host.inst.Main
	}
	if len(frozen) > 0 && !config.Has(acts, config.ActionFreeze) {
		e.Ops.Resume(frozen)
		frozen = nil
	} else if len(frozen) == 0 && canTouch && config.Has(acts, config.ActionFreeze) {
		if instant || tryFreeze() {
			frozen, _ = e.Ops.SuspendTree(freezeRoot)
			latency = time.Since(oa.Time)
		} else if claimedNow() {
			return // the instant path froze it and reports it
		}
	}

	// Freeze the rest of it. A stealer is rarely one process: a loader starts
	// it, it runs copies of itself, it has helpers. Freezing only the process
	// that touched the bait leaves the others free to upload, or to un-freeze it.
	var also []string
	blockToo := map[string]bool{}
	if len(frozen) > 0 && v.Tier == config.TierCritical && !test {
		grow := func(root uint32, img string) {
			if stopHost && hasPID(frozen, root) {
				// The instant path froze it already, with the browser.
				also = append(also, fmt.Sprintf("%s (pid %d)", filepath.Base(img), root))
				return
			}
			if more := e.Ops.SuspendMore(root, frozen); len(more) > 0 {
				frozen = append(frozen, more...)
				also = append(also, fmt.Sprintf("%s (pid %d)", filepath.Base(img), root))
			}
		}
		// Up from the browser's main process, past the browser itself (it
		// restarts itself to update): its starter by the host policy's rule,
		// then on by the usual one.
		for _, anc := range e.Ops.Ancestors(freezeRoot) {
			if stopHost && anc.PID != host.inst.Starter && sameImage(anc.Image, host.inst.Image) {
				continue
			}
			if stopHost && anc.PID == host.inst.Starter {
				if !e.starterFreezable(cls, *host, anc.PID, anc.Image) {
					break
				}
				grow(anc.PID, anc.Image)
				if cls.UserWritable(anc.Image) && !e.Ops.Verify(anc.Image).Valid {
					blockToo[anc.Image] = true
				}
				continue
			}
			if !e.partOfIt(cls, anc.PID, anc.Image) {
				break
			}
			grow(anc.PID, anc.Image)
			if cls.UserWritable(anc.Image) && !e.Ops.Verify(anc.Image).Valid {
				blockToo[anc.Image] = true
			}
		}
		if !sig.Valid && cls.UserWritable(image) {
			for _, p := range e.Ops.RunningImage(image) { // other running copies of the same unsigned file
				if p != oa.PID && !hasPID(frozen, p) && e.partOfIt(cls, p, image) {
					grow(p, image)
				}
			}
		}
		for _, h := range oa.Helpers { // doing its work for it (Finder copying for a script)
			if hasPID(frozen, h) {
				continue
			}
			if img, err := e.Ops.ImagePath(h); err == nil && e.touchable(h, img) {
				grow(h, img)
			}
		}
		for _, m := range teammates { // the others in a split-up sweep
			if hasPID(frozen, m.pid) || e.Ops.CreateTime(m.pid) != m.createTime || !e.touchable(m.pid, m.image) || e.isFrozen(m.pid, m.createTime) {
				continue
			}
			grow(m.pid, m.image)
			blockToo[m.image] = true
		}
		delete(blockToo, image)
	}

	a := &alerts.Alert{
		ID: alerts.NewID(now), Time: now, Kind: alerts.KindRead, Tier: v.Tier, Verdict: v,
		Learning: learning && v.Tier != config.TierCritical && len(cfg.Responses[v.Tier]) > 0, Test: test, Status: "open",
		Baits:   []alerts.BaitHit{hit},
		Process: &alerts.Process{PID: oa.PID, Image: image, User: oa.User, Signature: sig},
	}
	a.Instant = instant && len(frozen) > 0
	if access == "delete" {
		a.Kind = alerts.KindDelete
	}
	if access == "write" {
		a.Kind = alerts.KindWrite
	}
	if access == "swap" {
		a.Kind = alerts.KindClipper
	}
	if test {
		a.Kind = alerts.KindTest
	}
	if config.Has(acts, config.ActionFreeze) {
		if len(frozen) > 0 {
			detail := fmt.Sprintf("%d process(es) frozen", len(frozen))
			switch {
			case stopHost:
				// (config.Action.Done reads "frozen: …" as what was frozen.)
				detail += fmt.Sprintf(": that whole %s (from its main process, pid %d)", alerts.BrowserName(image), freezeRoot)
				if len(also) > 0 {
					detail += " and what started it: " + strings.Join(also, ", ")
				}
				if instant {
					detail += ", the moment it opened the bait"
				}
			default:
				if instant {
					detail += " the moment it opened the bait"
				}
				if len(also) > 0 {
					detail += "; with it: " + strings.Join(also, ", ")
				}
			}
			a.AddAction(config.ActionFreeze, nil, detail)
		} else if !canTouch {
			a.AddAction(config.ActionFreeze, fmt.Errorf("refused"), "protected system process")
		} else {
			a.AddAction(config.ActionFreeze, fmt.Errorf("could not suspend"), "")
		}
	}
	if goneFreeze {
		a.AddAction(config.ActionFreeze, fmt.Errorf("it had already exited"), "")
	}
	if latency > 0 {
		a.LatencyMS = latency.Milliseconds()
	}
	a.DeliveryMS = received.Sub(oa.Time).Milliseconds()

	// 5. Forensics while frozen.
	e.Ops.Forensics(oa.PID, a.Process)
	if host != nil && host.gone {
		a.Process.Exited = true
	}

	// 6. Remaining responses.
	var blocked, isolated, killAfter bool
	var adapters, alsoBlocked []string
	for _, act := range acts {
		switch act {
		case config.ActionBlockProgram:
			if stopHost {
				// Not the browser's program: that would cut your own windows
				// of it, and the stealer's copy is frozen. What started it is.
				var did []string
				for img := range blockToo {
					if e.Ops.BlockProgram(img) == nil {
						alsoBlocked = append(alsoBlocked, img)
						did = append(did, img)
					}
				}
				if len(did) > 0 {
					sort.Strings(did)
					a.AddAction(act, nil, config.StarterBlocked+strings.Join(did, ", "))
				}
				continue
			}
			if image == "" {
				a.AddAction(act, fmt.Errorf("unknown executable"), "")
				continue
			}
			err := e.Ops.BlockProgram(image)
			a.AddAction(act, err, image)
			blocked = err == nil
			for img := range blockToo {
				if e.Ops.BlockProgram(img) == nil {
					alsoBlocked = append(alsoBlocked, img)
				}
			}
		case config.ActionKill:
			if !canTouch {
				a.AddAction(act, fmt.Errorf("refused"), "protected system process")
				continue
			}
			if len(frozen) > 0 && wantsAutopsy(a, v, frozen) {
				// Ended once the autopsy has saved the evidence: killing it
				// now would destroy what it collected and where it was sending.
				killAfter = true
				a.AddAction(act, nil, "once the evidence was saved")
				continue
			}
			err := e.Ops.KillTree(freezeRoot)
			if stopHost && host.freezeStarter && hasPID(frozen, host.inst.Starter) {
				if err2 := e.Ops.KillTree(host.inst.Starter); err == nil {
					err = err2
				}
			}
			a.AddAction(act, err, "")
			if err == nil {
				frozen = nil
			}
		case config.ActionIsolate:
			err := e.Ops.Isolate()
			a.AddAction(act, err, "")
			isolated = err == nil
		case config.ActionDisableAdapters:
			names, err := e.Ops.DisableAdapters()
			a.AddAction(act, err, strings.Join(names, ", "))
			adapters = names
		}
	}

	if v.KeepRunning {
		name := alerts.BrowserName(image)
		detail := "it's the " + name + " you're using"
		if blocked {
			detail += "; the internet of every " + name + " window is cut instead"
		}
		if wouldStop {
			a.AddAction(config.ActionLeftRunning, nil, detail)
		}
	}
	e.describe(a, v)
	if stopHost {
		// "Possible stealer: a Chrome started suspended by ghost.exe opened your bait"
		a.Title = strings.Replace(a.Title, " inside "+alerts.BrowserName(image)+": a copy of it", ": "+host.which(), 1)
	}
	if v.DecoyOwner {
		a.Kind = alerts.KindDecoyRetired
	}
	if v.KeepRunning {
		name := alerts.BrowserName(image)
		if blocked {
			a.Summary += ". ABA left it running, since it's the browser you're using, and cut the internet of every " + name + " window instead"
		} else {
			a.Summary += ". ABA left it running: it's the browser you're using"
		}
	}

	quiet := quietly(a, v)
	if quiet {
		a.Status = alerts.StatusNoted
	}
	e.Ops.UpdateState(func(st *config.State) error {
		for _, p := range frozen {
			ct := e.Ops.CreateTime(p)
			img, _ := e.Ops.ImagePath(p)
			st.Frozen = append(st.Frozen, config.FrozenProcess{PID: p, CreateTime: ct, Image: img, AlertID: a.ID, Since: now})
		}
		if blocked && !st.IsBlocked(image) {
			st.Blocked = append(st.Blocked, config.BlockedProgram{Path: image, AlertID: a.ID, Since: now})
		}
		for _, img := range alsoBlocked {
			if !st.IsBlocked(img) {
				st.Blocked = append(st.Blocked, config.BlockedProgram{Path: img, AlertID: a.ID, Since: now})
			}
		}
		if isolated && st.Isolation == nil {
			st.Isolation = &config.Isolation{Since: now, AlertID: a.ID, Method: "wfp"}
		}
		if len(adapters) > 0 {
			st.DisabledAdapters = appendUnique(st.DisabledAdapters, adapters...)
			if st.Isolation == nil {
				st.Isolation = &config.Isolation{Since: now, AlertID: a.ID, Method: "adapters"}
			}
		}
		return nil
	})
	if err := e.Ops.SaveAlert(a); err != nil {
		e.Ops.Logf("save alert: %v", err)
	}
	// Lock them frozen (after they're on record, so the hold is never orphaned).
	if len(frozen) > 0 && !test {
		e.Ops.Hold(frozen)
	}

	// The alert is the whole browser instance's, and its starter's: what
	// any of them does next joins it (see joinHost, noteAfter).
	members := map[uint32]int64{oa.PID: createTime}
	if hostInst != nil {
		for _, p := range hostInst.PIDs {
			if _, ok := members[p]; !ok {
				members[p] = e.Ops.CreateTime(p)
			}
		}
		members[hostInst.Main] = hostInst.MainCreate
		for _, p := range frozen {
			if _, ok := members[p]; !ok {
				members[p] = e.Ops.CreateTime(p)
			}
		}
	}
	e.mu.Lock()
	for p, ct := range members {
		e.incidents[p] = &incident{alert: a, createTime: ct, last: time.Now(), wrecked: isWreck, quiet: quiet}
	}
	for pid, inc := range e.incidents {
		if time.Since(inc.last) > window {
			delete(e.incidents, pid)
		}
	}
	// What the event log said it did to the bait while this alert was being made.
	var after *alerts.Alert
	for p := range members {
		for _, h := range e.later[p] {
			if cp, ok := e.did(a, h); ok {
				after = cp
			}
		}
		delete(e.later, p)
	}
	loud := false // a quiet read that turned out to be more meanwhile
	if quiet && after != nil && after.Kind != alerts.KindRead {
		loud, a.Status, after.Status = true, "open", "open"
		for _, inc := range e.incidents {
			if inc.alert == a {
				inc.quiet = false
			}
		}
	}
	e.mu.Unlock()
	if after != nil {
		e.Ops.SaveAlert(after)
	}
	if loud {
		e.tell(after)
		return
	}
	if quiet {
		// It's in the history (`aba alerts`), where it can be trusted from;
		// nobody is interrupted for a program that looks legitimate. (Only
		// someone who asked for every alert on their phone, "Everything" in
		// setup, still gets it there.)
		e.Ops.Logf("alert %s: %s read %s, which looks legitimate: noted quietly, no popup", a.ID, image, baitID)
		if cfg.PhoneMinTier == config.TierInfo {
			e.Ops.NotifyPhone(a)
		}
		return
	}

	// Script hosts and runtimes are never quieted: the next script could be a
	// different one. Neither are critical alerts.
	if !test && len(a.Actions) == 0 && !v.DecoyOwner && v.Tier != config.TierCritical &&
		!classify.ScriptHost(image) && e.repeat(image, baitID, now) {
		// Same program, same bait, nothing done about it: it's in the history,
		// but don't pop up on every launch of an app you haven't marked yet.
		e.Ops.Logf("alert %s: repeat of %s reading %s, not notified again", a.ID, image, baitID)
		return
	}
	e.Ops.NotifyDesktop(a)
	if test || v.Tier.Rank() >= cfg.PhoneMinTier.Rank() {
		e.Ops.NotifyPhone(a)
	}
	if v.DecoyOwner {
		e.Ops.RetireDecoy(baitID, a.Summary)
	}
	if test {
		// Now, not after the autopsy, which takes a second or two: `aba test`
		// has its alert already, and the next test's request may arrive
		// meanwhile. Clearing later would wipe that one.
		e.Ops.ClearTest()
	}
	// 7. The autopsy, now that the alert is out: what had it already taken?
	if wantsAutopsy(a, v, frozen) {
		c := autopsy.Case{AlertID: a.ID, Test: test, PID: oa.PID, Image: image, Tree: append([]uint32(nil), a.Process.TreePIDs...),
			Frozen: append([]uint32(nil), frozen...), BaitAt: oa.Time, Conns: append([]procinfo.Conn(nil), a.Process.Connections...)}
		if oa.Swap != nil {
			c.Wallet = oa.Swap.Replacement
		}
		procs := append(append([]uint32{oa.PID}, frozen...), a.Process.TreePIDs...)
		switch {
		case host == nil && !test:
			// A genuine browser frozen for something else (a sweep): its
			// opens of its own data are the browser at work.
			c.Own = e.ownApps(cls, procs)
		case stopHost && !host.inst.CreatedSuspended:
			// A browser that had been running as one when something in it
			// went through the fake profile: its opens of its own data can't
			// be told apart from that code's. ("Can't tell", not "read".)
			// One created suspended never ran as a browser: everything it
			// opened, it opened for the stealer.
			c.Running = e.ownApps(cls, procs)
		}
		var kill []uint32
		if killAfter {
			kill = append(kill, freezeRoot)
			if stopHost && host.freezeStarter && hasPID(frozen, host.inst.Starter) {
				kill = append(kill, host.inst.Starter)
			}
		}
		if test {
			e.autopsy(a, c) // before the test reader is ended below
		} else {
			go e.autopsy(a, c, kill...)
		}
	}
	if test {
		e.Ops.KillTree(oa.PID)
		// The test reader is gone: don't leave it on the frozen list.
		e.Ops.UpdateState(func(st *config.State) error {
			var keep []config.FrozenProcess
			for _, f := range st.Frozen {
				if f.AlertID != a.ID {
					keep = append(keep, f)
				}
			}
			st.Frozen = keep
			return nil
		})
	}
	e.Ops.Logf("alert %s: %s [%s] actions=%d latency=%dms (delivery %dms)", a.ID, a.Title, a.Tier, len(a.Actions), a.LatencyMS, a.DeliveryMS)
}

// noteAfter records what a program already caught inside its open of a bait
// went on to do to it. Windows doesn't always say what an open asked for, so
// a program caught there is reported as having opened the bait. The event
// log, a moment later, says when it overwrote or deleted it: then the alert
// says so, because that's ransomware or a wiper, not a stealer.
func (e *Engine) noteAfter(oa *detect.Access) {
	access := ""
	switch oa.Op {
	case detect.OpRead:
		// Another bait it (or another process of the browser instance it's
		// part of) read: listed in the same alert.
		access = "read"
	case detect.OpWrite:
		access = "write"
	case detect.OpDelete:
		access = "delete"
	default:
		return
	}
	baitID, ok := e.IsBait(oa.Path)
	if !ok {
		return
	}
	e.mu.Lock()
	hit := alerts.BaitHit{ID: baitID, Name: e.baitNames[baitID], Path: oa.Path, Access: access, Time: oa.Time}
	inc := e.incidents[oa.PID]
	if inc == nil {
		// Its alert isn't on record yet: kept for when it is (see handle).
		if len(e.later) > 256 {
			e.later = map[uint32][]alerts.BaitHit{}
		}
		if len(e.later[oa.PID]) < 16 {
			e.later[oa.PID] = append(e.later[oa.PID], hit)
		}
		e.mu.Unlock()
		return
	}
	cp, changed := e.did(inc.alert, hit)
	loud := false
	if changed && inc.quiet && cp.Kind != alerts.KindRead {
		// Noted quietly as a read; it went on to overwrite or delete the
		// bait: that you hear about.
		loud, inc.alert.Status, cp.Status = true, "open", "open"
		for _, x := range e.incidents {
			if x.alert == inc.alert {
				x.quiet = false
			}
		}
	}
	e.mu.Unlock()
	if changed {
		e.Ops.SaveAlert(cp)
	}
	if loud {
		e.tell(cp)
	}
}

// did adds to alert a what its program went on to do to a bait (hit: a write
// or a delete), and returns a copy to save. An alert about a read becomes one
// about what was done to the file. Called with e.mu held.
func (e *Engine) did(a *alerts.Alert, hit alerts.BaitHit) (*alerts.Alert, bool) {
	if hit.Access == "read" {
		return e.addHit(a, hit)
	}
	for _, h := range a.Baits {
		if strings.EqualFold(h.Path, hit.Path) && h.Access == hit.Access {
			return nil, false
		}
	}
	a.Baits = append(a.Baits, hit)
	if a.Kind == alerts.KindRead && !a.Test {
		what, to, threat := "overwrote", "overwrite", "Possible ransomware"
		a.Kind = alerts.KindWrite
		if hit.Access == "delete" {
			what, to, threat, a.Kind = "deleted", "delete", "Possible wiper or ransomware", alerts.KindDelete
		}
		if a.Tier == config.TierCritical {
			a.Title = threat + ": " + a.ExeName() + " " + what + " your bait"
		} else {
			a.Title = a.ExeName() + " " + what + " a bait"
		}
		a.Verdict.Reasons = append(a.Verdict.Reasons[:len(a.Verdict.Reasons):len(a.Verdict.Reasons)],
			"it went on to "+to+" the bait: that's what ransomware and wipers do to a file, not what a stealer does")
	}
	cp := *a
	cp.Baits = append([]alerts.BaitHit(nil), a.Baits...)
	return &cp, true
}

// wantsAutopsy: a program caught as a stealer or clipper (or `aba test`'s),
// or anything frozen, gets looked into. A warning about a program that's
// still running free doesn't: it's no verdict that it stole anything.
//
// Nor does the browser you're using that was left running (classify.Verdict
// KeepRunning): it reads your real cookies and passwords all day, so the
// autopsy would announce a theft that is only your browser at work.
func wantsAutopsy(a *alerts.Alert, v classify.Verdict, frozen []uint32) bool {
	if a.Process == nil || v.DecoyOwner || v.Ignored || v.KeepRunning {
		return false
	}
	switch a.Kind {
	case alerts.KindRead, alerts.KindWrite, alerts.KindDelete, alerts.KindClipper, alerts.KindTest:
	default:
		return false
	}
	return v.Tier == config.TierCritical || len(frozen) > 0 || a.Test
}

// autopsy runs the autopsy of a's program and adds what it found to a. kill
// are processes to end (with what they started) once it's done: the
// configured response waited for the evidence.
func (e *Engine) autopsy(a *alerts.Alert, c autopsy.Case, kill ...uint32) {
	defer func() {
		if r := recover(); r != nil {
			e.Ops.Logf("PANIC in the autopsy of %s: %v", c.AlertID, r)
		}
		for _, k := range kill {
			if err := e.Ops.KillTree(k); err != nil {
				e.Ops.Logf("alert %s: ending pid %d after the autopsy: %v", c.AlertID, k, err)
			}
		}
	}()
	res := e.Ops.Autopsy(c)
	if res == nil {
		return
	}
	e.mu.Lock()
	a.Autopsy = res
	cp := *a
	cp.Baits = append([]alerts.BaitHit(nil), a.Baits...)
	e.mu.Unlock()
	if err := e.Ops.SaveAlert(&cp); err != nil {
		e.Ops.Logf("save alert %s with its autopsy: %v", a.ID, err)
	}
	if res.Answer == alerts.AnswerRead && !c.Test {
		e.Ops.NotifyAutopsy(&cp)
	}
}

func hasPID(pids []uint32, pid uint32) bool {
	for _, p := range pids {
		if p == pid {
			return true
		}
	}
	return false
}

// partOfIt reports whether a process related to a critical reader (the
// program that started it, another copy of it) should be frozen with it: it
// would be critical itself if it had read the bait. A terminal you typed the
// command into is; Explorer, a signed launcher or anything elevated isn't.
func (e *Engine) partOfIt(cls *classify.Classifier, pid uint32, image string) bool {
	if image == "" || !e.touchable(pid, image) || !e.Ops.UserSession(pid) || e.Ops.Elevated(pid) || e.Ops.IsSelf(image) {
		return false
	}
	v := cls.Final(image, pid, classify.Bait{}, e.Ops.Verify(image))
	return !v.Ignored && v.Tier == config.TierCritical
}

// isFrozen reports whether pid is already on record as frozen (freezing it
// again would stack a second suspension).
func (e *Engine) isFrozen(pid uint32, createTime int64) bool {
	found := false
	e.Ops.UpdateState(func(st *config.State) error {
		for _, f := range st.Frozen {
			found = found || (f.PID == pid && f.CreateTime == createTime)
		}
		return nil
	})
	return found
}

// joinTeam records that pid read baitID and, when the programs that read
// baits lately went through sweepApps different apps' data between them (and
// there's more than one of them), returns those apps and programs. One program
// doing that alone is an ordinary sweep (see touch).
func (e *Engine) joinTeam(pid uint32, baitID, image string, now time.Time) (units []string, members []teamRead) {
	ct := e.Ops.CreateTime(pid)
	unit := sweepUnit(baitID)
	e.mu.Lock()
	defer e.mu.Unlock()
	keep := e.team[:0]
	known := false
	for _, r := range e.team {
		if now.Sub(r.at) < window {
			keep = append(keep, r)
			known = known || (r.pid == pid && r.unit == unit && (r.createTime == ct || ct == 0 || r.createTime == 0))
		}
	}
	e.team = keep
	if !known {
		e.team = append(e.team, teamRead{pid: pid, createTime: ct, unit: unit, image: image, at: now})
	}
	seenUnit, seenPID := map[string]bool{}, map[uint32]bool{}
	for _, r := range e.team {
		if !seenUnit[r.unit] {
			seenUnit[r.unit] = true
			units = append(units, r.unit)
		}
		if !seenPID[r.pid] {
			seenPID[r.pid] = true
			members = append(members, r)
		}
	}
	if len(units) < sweepApps || len(members) < 2 {
		return nil, nil
	}
	sort.Strings(units)
	return units, members
}

// teamVerdict is the critical verdict for a reader that's part of a sweep
// split over several programs.
func (e *Engine) teamVerdict(v classify.Verdict, units []string, programs int) classify.Verdict {
	names := e.unitNames(units)
	who := "Several programs"
	if programs > 1 {
		who = fmt.Sprintf("%d programs", programs)
	}
	why := fmt.Sprintf("%s together read the data of %d different apps within %d minutes (%s), this one among them: a stealer splitting its work up so that no single program looks like one",
		who, len(units), int(window.Minutes()), strings.Join(names, ", "))
	return classify.Verdict{Tier: config.TierCritical, Swept: units, Evasion: v.Evasion, Reasons: append([]string{why}, v.Reasons...)}
}

// filesUnit stands for all the plain-file baits together (passwords.txt on
// the Desktop, in Documents…).
const filesUnit = "files"

// sweepUnit is what a bait counts as in a sweep. Plain files in your folders
// all count as one: OneDrive, a backup or zipping up Documents legitimately
// reads them all. Each app's data (a browser, Discord, a wallet) counts on its
// own: nothing but a backup of AppData or a stealer goes through those.
func sweepUnit(baitID string) string {
	if s, ok := baits.ByID(baitID); ok && s.Kind == baits.KindFile {
		return filesUnit
	}
	return baitID
}

// touch records that pid opened baitID and returns every sweep unit (see
// sweepUnit) it opened within the window, this one included.
func (e *Engine) touch(pid uint32, baitID string, now time.Time) []string {
	ct := e.Ops.CreateTime(pid)
	e.mu.Lock()
	defer e.mu.Unlock()
	for p, sw := range e.touched {
		fresh := false
		for _, t := range sw.baits {
			fresh = fresh || now.Sub(t) < window
		}
		if !fresh {
			delete(e.touched, p)
		}
	}
	sw := e.touched[pid]
	// A different process that reuses the PID starts afresh. (ct is 0 once the
	// process has exited: its late audit events still count.)
	if sw == nil || (ct != 0 && sw.createTime != 0 && sw.createTime != ct) {
		sw = &sweep{createTime: ct, baits: map[string]time.Time{}}
		e.touched[pid] = sw
	}
	if sw.createTime == 0 {
		sw.createTime = ct
	}
	sw.baits[sweepUnit(baitID)] = now
	var ids []string
	for id, t := range sw.baits {
		if now.Sub(t) < window {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// SweepSuspect returns which of pids (programs paused inside an open of path)
// would complete a sweep by opening it: the one that already read two other
// apps' data within the window. Instant freeze normally identifies the opener
// by letting the open go through and seeing who wakes, so a quick sweeper got
// the third app's data (and could even exit) before it was frozen. With a
// suspect known, it's decided while the open is still paused. 0 if none, or
// more than one.
func (e *Engine) SweepSuspect(path string, pids []uint32) uint32 {
	now := time.Now()
	e.mu.Lock()
	baitID, ok := e.index[paths.Key(path)]
	if !ok {
		e.mu.Unlock()
		return 0
	}
	unit := sweepUnit(baitID)
	var hit uint32
	var hitCT int64
	n := 0
	for _, pid := range pids {
		sw := e.touched[pid]
		if pid == e.SelfPID || sw == nil {
			continue
		}
		others := 0
		for u, t := range sw.baits {
			if u != unit && now.Sub(t) < window {
				others++
			}
		}
		if others+1 >= sweepApps {
			hit, hitCT = pid, sw.createTime
			n++
		}
	}
	e.mu.Unlock()
	if n != 1 {
		return 0
	}
	if ct := e.Ops.CreateTime(hit); ct != 0 && hitCT != 0 && ct != hitCT {
		return 0 // the PID was reused by another process
	}
	return hit
}

// sweepable: a sweep only counts for ordinary programs in a user session.
// Services and admin tools (backup, antivirus) are out of reach of a
// user-level stealer, and `aba test` is a test.
func (e *Engine) sweepable(pid uint32) bool {
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == pid {
		return false
	}
	if !e.userSession(pid) {
		return false
	}
	// Once it has exited its elevation can't be checked; it's judged by what it read.
	return e.Ops.CreateTime(pid) == 0 || !e.Ops.Elevated(pid)
}

// userSession reports whether pid is an ordinary user's program rather than
// a Windows service. While it runs, its session says so. A fast reader (or a
// stealer that grabs everything and quits) may be gone by the time the audit
// event arrives; then the account it read as, from that event, says so.
func (e *Engine) userSession(pid uint32) bool {
	if e.Ops.UserSession(pid) {
		return true
	}
	if e.Ops.CreateTime(pid) != 0 {
		return false // running, in session 0
	}
	e.mu.Lock()
	sid := e.sids[pid]
	e.mu.Unlock()
	return sid != "" && !procinfo.ServiceAccount(sid)
}

// sweepVerdict turns a verdict into a critical one: the reader went through
// several apps' data.
func (e *Engine) unitNames(units []string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var names []string
	for _, id := range units {
		n := e.baitNames[id]
		switch {
		case id == filesUnit:
			n = "your password/recovery files"
		case n == "":
			n = id
		}
		names = append(names, n)
	}
	return names
}

// wreckFolders is how many different folders a program must rewrite baits in,
// within the window, to be stopped as ransomware whatever it is.
const wreckFolders = 2

// wreck records that pid opened the document bait at path to change it, and
// returns the folders it has done that in within the window. Only your
// documents count (the files in your Desktop, Documents and home folder):
// that's where ransomware goes, and nothing legitimate rewrites files it
// didn't make in one folder after another. An app's own data doesn't count:
// the app, a cleaner or a sync client rewrites that all the time. Deletes
// are only counted for a script host (see handle): you delete files in
// several folders in Explorer, and a sync client moves them, all the time.
func (e *Engine) wreck(pid uint32, baitID, path string, now time.Time) []string {
	if sweepUnit(baitID) != filesUnit {
		return nil
	}
	ct := e.Ops.CreateTime(pid)
	dir := strings.ToLower(filepath.Dir(path))
	e.mu.Lock()
	defer e.mu.Unlock()
	for p, sw := range e.wrecked {
		fresh := false
		for _, t := range sw.baits {
			fresh = fresh || now.Sub(t) < window
		}
		if !fresh {
			delete(e.wrecked, p)
		}
	}
	sw := e.wrecked[pid]
	if sw == nil || (ct != 0 && sw.createTime != 0 && sw.createTime != ct) {
		sw = &sweep{createTime: ct, baits: map[string]time.Time{}}
		e.wrecked[pid] = sw
	}
	if sw.createTime == 0 {
		sw.createTime = ct
	}
	sw.baits[dir] = now
	var dirs []string
	for d, t := range sw.baits {
		if now.Sub(t) < window {
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// wreckVerdict turns a verdict into a critical one: the program rewrote
// files of yours in several folders (access "write"), or a script deleted
// them there ("delete").
func (e *Engine) wreckVerdict(v classify.Verdict, dirs []string, access string) classify.Verdict {
	names := make([]string, len(dirs))
	for i, d := range dirs {
		names[i] = filepath.Base(d)
	}
	did, moral := "went to overwrite", "ransomware and wipers rewrite everything they find, real programs only change what you open in them"
	if access == "delete" {
		did, moral = "deleted", "a wiper, or ransomware removing what it has encrypted a copy of, goes through everything it finds"
	}
	why := fmt.Sprintf("it %s files of yours in %d different folders within %d minutes (%s): %s",
		did, len(dirs), int(window.Minutes()), strings.Join(names, ", "), moral)
	return classify.Verdict{Tier: config.TierCritical, Reasons: append([]string{why}, v.Reasons...)}
}

func (e *Engine) sweepVerdict(v classify.Verdict, swept []string) classify.Verdict {
	names := e.unitNames(swept)
	why := fmt.Sprintf("it read the data of %d different apps within %d minutes (%s): stealers sweep everything, real apps only touch their own",
		len(swept), int(window.Minutes()), strings.Join(names, ", "))
	return classify.Verdict{Tier: config.TierCritical, Swept: swept, Reasons: append([]string{why}, v.Reasons...)}
}

// repeatWindow is how long a no-action alert for the same program and bait
// stays quiet after its first notification.
const repeatWindow = 12 * time.Hour

func (e *Engine) repeat(image, baitID string, now time.Time) bool {
	key := strings.ToLower(image) + "|" + baitID
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := e.seen[key]; ok && now.Sub(last) < repeatWindow {
		return true
	}
	e.seen[key] = now
	return false
}

func (e *Engine) describe(a *alerts.Alert, v classify.Verdict) {
	exe := a.ExeName()
	what, threat := "read", "Possible stealer"
	switch a.Kind {
	case alerts.KindDelete:
		what, threat = "deleted", "Possible wiper or ransomware"
	case alerts.KindWrite:
		what, threat = "changed", "Possible ransomware"
	}
	if a.Instant {
		// Caught inside the open: what it asked to do, not what it did.
		switch a.Kind {
		case alerts.KindDelete:
			what = "went to delete"
		case alerts.KindWrite:
			what = "went to overwrite"
		default:
			what = "opened"
		}
	}
	switch {
	case a.Test && len(a.Baits) > 0 && a.Baits[0].Access == "swap":
		a.Title = "Test detection: " + exe + " was caught swapping a wallet address on the clipboard"
	case a.Kind == alerts.KindClipper:
		a.Title = "Clipper caught: " + exe + " swapped a wallet address on your clipboard"
	case a.Test && a.Instant:
		a.Title = "Test detection: " + exe + " was frozen the moment it opened a bait"
	case a.Test:
		a.Title = "Test detection: " + exe + " read a bait"
	case v.DecoyOwner && v.Host:
		a.Title = alerts.BrowserName(exe) + " made a fake profile's folder its own: ABA moved the fake profile"
	case v.DecoyOwner:
		a.Title = exe + " is installed: retiring its decoy"
	case v.KeepRunning:
		a.Title = "Something inside your " + alerts.BrowserName(exe) + " " + what + " a bait"
		if a.Did(config.ActionBlockProgram) {
			a.Title += ": its internet is cut"
		}
	case v.Host && v.Tier == config.TierCritical:
		// (The browser itself is named by what gave it away: see handle.)
		a.Title = threat + " inside " + alerts.BrowserName(exe) + ": a copy of it " + what + " your bait"
		if a.Process != nil && a.Process.Exited {
			a.Title = threat + " inside " + alerts.BrowserName(exe) + ": a copy of it that exited at once " + what + " your bait"
		}
	case v.Tier == config.TierCritical:
		a.Title = threat + ": " + exe + " " + what + " your bait"
	case v.Tier == config.TierWarn:
		a.Title = exe + " " + what + " a bait"
	default:
		a.Title = exe + " " + what + " a bait (looks legitimate)"
	}
	if len(v.Reasons) > 0 {
		a.Summary = v.Reasons[0]
	}
	if a.Instant {
		a.Summary = "Caught the moment it opened the bait (instant freeze). " + a.Summary
	}
}

// ClipboardBait is the bait ID of the fake wallet address ABA puts on the
// clipboard (package clipbait). It's not a file, so it's never in the index.
const ClipboardBait = "clipboard"

const clipboardBaitName = "Clipboard (a fake wallet address)"

// swapVerdict: a program replaced ABA's fake wallet address with another
// address. Nothing legitimate does that, whatever it is and whoever signed
// it, so it's critical; no rule makes it otherwise.
func swapVerdict(sw *detect.Swap) classify.Verdict {
	why := "it replaced the wallet address ABA put on the clipboard with a different one: that's a clipper, malware that makes whatever you paste into your wallet send the money to the attacker"
	if sw.Replacement == "" {
		why = "it wiped the wallet address ABA put on the clipboard the moment it appeared, and did it again each time: a clipper that tried to swap in its own address"
	}
	reasons := []string{why}
	if sw.How != "" {
		reasons = append(reasons, "how ABA knows it was this program: "+sw.How)
	}
	if sw.Replacement != "" {
		reasons = append(reasons, "the address it swapped in (the attacker's): "+sw.Replacement)
	}
	if sw.Keyed {
		reasons = append(reasons, "the bait address: "+sw.Bait+" (a real one, whose key ABA holds: anything sent to it isn't lost, see `aba clipboard key`)")
	} else {
		reasons = append(reasons, "the bait address: "+sw.Bait+" (invalid on purpose: no wallet accepts it)")
	}
	return classify.Verdict{Tier: config.TierCritical, Reasons: reasons}
}

// without is acts minus drop.
func without(acts []config.Action, drop ...config.Action) []config.Action {
	var out []config.Action
	for _, a := range acts {
		if !config.Has(drop, a) {
			out = append(out, a)
		}
	}
	return out
}

func appendUnique(xs []string, add ...string) []string {
	for _, a := range add {
		found := false
		for _, x := range xs {
			found = found || strings.EqualFold(x, a)
		}
		if !found {
			xs = append(xs, a)
		}
	}
	return xs
}

// SystemAlert raises an alert not tied to a reader (tamper, missing bait, retirement).
func (e *Engine) SystemAlert(kind string, tier config.Tier, title, summary string, hits []alerts.BaitHit) *alerts.Alert {
	now := time.Now()
	a := &alerts.Alert{ID: alerts.NewID(now), Time: now, Kind: kind, Tier: tier, Title: title, Summary: summary,
		Baits: hits, Status: "open", Verdict: classify.Verdict{Tier: tier, Reasons: []string{summary}}}
	e.Ops.SaveAlert(a)
	e.Ops.NotifyDesktop(a)
	e.mu.Lock()
	min := config.TierWarn
	if e.cfg != nil {
		min = e.cfg.PhoneMinTier
	}
	e.mu.Unlock()
	if tier.Rank() >= min.Rank() {
		e.Ops.NotifyPhone(a)
	}
	return a
}

// ProcessDetails is the default Forensics implementation.
func ProcessDetails(pid uint32, p *alerts.Process) {
	if !procinfo.Alive(pid, 0) {
		p.Exited = true
	}
	p.CommandLine, _ = procinfo.CommandLine(pid)
	p.Dir = procinfo.WorkingDir(pid)
	if snap, err := procinfo.Snapshot(); err == nil {
		p.Parents = procinfo.ParentChain(snap, pid, 4)
		p.TreePIDs = procinfo.Tree(snap, pid)
	}
	pids := p.TreePIDs
	if len(pids) == 0 {
		pids = []uint32{pid}
	}
	p.Connections, _ = procinfo.Connections(pids)
	if p.Image != "" {
		p.SHA256, _ = procinfo.FileSHA256(p.Image)
	}
	p.Origin = origin.Find(originCandidates(p)...)
}

// originCandidates are the files whose download mark says where this came
// from: the script a runtime runs, the program itself, then what started it
// (a downloaded installer that unpacked the stealer into Temp).
func originCandidates(p *alerts.Process) []string {
	var files []string
	if classify.ScriptHost(p.Image) {
		if s, _ := classify.DroppedScript(p.CommandLine); s != "" {
			files = append(files, s)
		}
	}
	files = append(files, p.Image)
	for _, par := range p.Parents {
		if !par.Exited && par.Image != "" {
			files = append(files, par.Image)
		}
	}
	return files
}
