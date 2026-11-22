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
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
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
	claimed     map[uint32]time.Time     // PIDs the instant path is handling
	seen        map[string]time.Time     // program|bait -> last notification, for alerts with no action
	touched     map[uint32]*sweep        // baits each process opened recently
	sids        map[uint32]string        // account a process read baits as (detect.Access.UserID), as the watcher reported it
	pending     map[uint32]chan struct{} // instant decisions in progress
	eventFrozen map[uint32]time.Time     // processes the event-log path froze
	marks       map[uint32]mark          // processes seen using a trick to dodge detection
	team        []teamRead               // recent bait reads by anyone, for sweeps split over several processes
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
}

// aggregation window: further bait hits by the same process join one alert.
const window = 2 * time.Minute

func New(ops Ops, selfPID uint32) *Engine {
	return &Engine{Ops: ops, SelfPID: selfPID, incidents: map[uint32]*incident{}, claimed: map[uint32]time.Time{},
		seen: map[string]time.Time{}, touched: map[uint32]*sweep{}, sids: map[uint32]string{},
		pending: map[uint32]chan struct{}{}, eventFrozen: map[uint32]time.Time{}, marks: map[uint32]mark{}}
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

const disguiseWhy = "it's a copy of ABA's own program reading a bait without admin rights: ABA never does that, so something is using it as a disguise"

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
		return false, image + " runs as administrator"
	}
	sig := e.Ops.Verify(image)
	v := cls.Final(image, pid, e.baitRef(baitID), sig)
	exempt := cls.SweepExempt(image, pid, &sig)
	if swept := e.touch(pid, baitID, time.Now()); len(swept) >= sweepApps && !exempt {
		v = e.sweepVerdict(v, swept)
	}
	if !v.Builtin && !v.DecoyOwner {
		// (Elevated copies of ABA were let through above.)
		if _, disguise := e.ownCopy(pid, image); disguise {
			v = evasive(v, disguiseWhy)
		} else if why := e.evasion(pid); why != "" && !cls.TricksAllowed(image, pid, baitID, &sig) {
			v = evasive(v, why)
		}
	}
	if v.Ignored || v.DecoyOwner {
		done(false)
		return false, image + " is ignored or the real app"
	}
	if !exempt && v.Tier != config.TierCritical {
		if units, _ := e.joinTeam(pid, baitID, image, time.Now()); units != nil {
			v = e.teamVerdict(v, units, 0)
		}
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
	e.handle(&detect.Access{PID: pid, Path: path, Op: detect.OpRead, Time: at}, frozen)
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
			return // the instant path already caught and is reporting this process
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
	if access == "read" {
		swept = e.touch(oa.PID, baitID, time.Now())
		if len(swept) >= sweepApps && !e.sweepable(oa.PID) {
			swept = nil
		}
	}

	e.mu.Lock()
	cfg, cls, name := e.cfg, e.classifier, e.baitNames[baitID]
	hit := alerts.BaitHit{ID: baitID, Name: name, Path: oa.Path, Access: access, Time: oa.Time}
	if access == "swap" {
		hit.Name, hit.Path = clipboardBaitName, "the clipboard"
	}
	if inc := e.incidents[oa.PID]; !instant && inc != nil && len(swept) >= sweepApps && inc.alert.Tier != config.TierCritical {
		// It started out looking harmless and has now read several apps' data:
		// handle it again as a sweep, with the full response.
		delete(e.incidents, oa.PID)
	}
	if inc := e.incidents[oa.PID]; access == "swap" && inc != nil && inc.alert.Tier != config.TierCritical {
		delete(e.incidents, oa.PID) // same: now it's a caught clipper
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
			e.mu.Unlock()
			e.Ops.SaveAlert(a)
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
		if access == "delete" {
			return nil // deleting isn't exfiltration; notify + auto-repair instead
		}
		return cfg.ActionsFor(t, now)
	}

	isSweep := len(swept) >= sweepApps

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
	if pre.Ignored && !instant && (pre.Builtin || !evading) {
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.Path, image, strings.Join(pre.Reasons, "; "))
		return
	}
	if evading && !pre.Builtin && pre.Tier != config.TierCritical {
		pre = classify.Verdict{Tier: config.TierCritical, Reasons: pre.Reasons} // freeze first, like any critical reader
	}
	frozen := preFrozen
	var latency time.Duration
	canTouch := e.touchable(oa.PID, image)
	if instant {
		latency = time.Since(oa.Time)
	} else if canTouch && config.Has(actionsFor(pre.Tier), config.ActionFreeze) {
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
	var teammates []teamRead
	if !test && access == "read" && !v.DecoyOwner && !v.Builtin && e.sweepable(oa.PID) && !cls.SweepExempt(image, oa.PID, &sig) {
		if units, members := e.joinTeam(oa.PID, baitID, image, now); units != nil && len(v.Swept) < sweepApps {
			v = e.teamVerdict(v, units, len(members))
			for _, m := range members {
				if m.pid != oa.PID {
					teammates = append(teammates, m)
				}
			}
		}
	}
	if startedAs != "" {
		v.Reasons = append(v.Reasons, "its file was renamed after it started (it was started as "+startedAs+")")
	}
	acts := actionsFor(v.Tier)
	if v.DecoyOwner {
		acts = nil
	}
	if len(frozen) > 0 && !config.Has(acts, config.ActionFreeze) {
		e.Ops.Resume(frozen)
		frozen = nil
	} else if len(frozen) == 0 && canTouch && config.Has(acts, config.ActionFreeze) {
		if instant || tryFreeze() {
			frozen, _ = e.Ops.SuspendTree(oa.PID)
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
			if more := e.Ops.SuspendMore(root, frozen); len(more) > 0 {
				frozen = append(frozen, more...)
				also = append(also, fmt.Sprintf("%s (pid %d)", filepath.Base(img), root))
			}
		}
		for _, anc := range e.Ops.Ancestors(oa.PID) {
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
	if access == "swap" {
		a.Kind = alerts.KindClipper
	}
	if test {
		a.Kind = alerts.KindTest
	}
	if config.Has(acts, config.ActionFreeze) {
		if len(frozen) > 0 {
			detail := fmt.Sprintf("%d process(es) frozen", len(frozen))
			if instant {
				detail += " the moment it opened the bait"
			}
			if len(also) > 0 {
				detail += "; with it: " + strings.Join(also, ", ")
			}
			a.AddAction(config.ActionFreeze, nil, detail)
		} else if !canTouch {
			a.AddAction(config.ActionFreeze, fmt.Errorf("refused"), "protected system process")
		} else {
			a.AddAction(config.ActionFreeze, fmt.Errorf("could not suspend"), "")
		}
	}
	if latency > 0 {
		a.LatencyMS = latency.Milliseconds()
	}
	a.DeliveryMS = received.Sub(oa.Time).Milliseconds()

	// 5. Forensics while frozen.
	e.Ops.Forensics(oa.PID, a.Process)

	// 6. Remaining responses.
	var blocked, isolated bool
	var adapters, alsoBlocked []string
	for _, act := range acts {
		switch act {
		case config.ActionBlockProgram:
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
			err := e.Ops.KillTree(oa.PID)
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

	e.describe(a, v)
	if v.DecoyOwner {
		a.Kind = alerts.KindDecoyRetired
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

	e.mu.Lock()
	e.incidents[oa.PID] = &incident{alert: a, createTime: createTime, last: time.Now()}
	for pid, inc := range e.incidents {
		if time.Since(inc.last) > window {
			delete(e.incidents, pid)
		}
	}
	e.mu.Unlock()

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
		e.Ops.KillTree(oa.PID)
		e.Ops.ClearTest()
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
	what := "read"
	if a.Kind == alerts.KindDelete {
		what = "deleted"
	}
	if a.Instant {
		what = "opened"
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
	case v.DecoyOwner:
		a.Title = exe + " is installed: retiring its decoy"
	case v.Tier == config.TierCritical:
		a.Title = "Possible stealer: " + exe + " " + what + " your bait"
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
	reasons = append(reasons, "the fake address: "+sw.Bait+" (it's invalid on purpose: no wallet accepts it)")
	return classify.Verdict{Tier: config.TierCritical, Reasons: reasons}
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
}
