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
package engine

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/evtlog"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Ops are the side effects the engine needs; the service provides real ones.
type Ops interface {
	ImagePath(pid uint32) (string, error)
	CreateTime(pid uint32) int64
	Verify(path string) authenticode.Result
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
	ClearTest()
	Logf(format string, args ...any)
}

// TestRequest marks a reader process started by `aba test`.
type TestRequest struct {
	PID   uint32    `json:"pid"`
	Nonce string    `json:"nonce"`
	Since time.Time `json:"since"`
}

// Engine is safe for concurrent use.
type Engine struct {
	Ops     Ops
	SelfPID uint32

	mu         sync.Mutex
	cfg        *config.Config
	classifier *classify.Classifier
	index      map[string]string // lower path -> bait id
	baitNames  map[string]string
	incidents  map[uint32]*incident
}

type incident struct {
	alert      *alerts.Alert
	createTime int64
	last       time.Time
}

// aggregation window: further bait hits by the same process join one alert.
const window = 2 * time.Minute

func New(ops Ops, selfPID uint32) *Engine {
	return &Engine{Ops: ops, SelfPID: selfPID, incidents: map[uint32]*incident{}}
}

// Configure (re)loads config and the bait index.
func (e *Engine) Configure(cfg *config.Config, st *config.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	e.classifier = &classify.Classifier{Env: classify.DefaultEnv(), Ignore: cfg.Ignore}
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

// processes we never suspend or kill (would hang or crash Windows / the desktop).
var neverTouch = map[string]bool{
	"system": true, "csrss.exe": true, "lsass.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "smss.exe": true, "svchost.exe": true, "explorer.exe": true, "dwm.exe": true,
	"msmpeng.exe": true, "fontdrvhost.exe": true, "lsaiso.exe": true, "registry": true,
	"memory compression": true, "secure system": true, "sihost.exe": true, "ctfmon.exe": true,
	"audiodg.exe": true, "conhost.exe": true, "runtimebroker.exe": true, "searchhost.exe": true,
}

func (e *Engine) touchable(pid uint32, image string) bool {
	if pid == 0 || pid == 4 || pid == e.SelfPID {
		return false
	}
	return !neverTouch[strings.ToLower(filepath.Base(image))]
}

// DecideInstant runs while a bait opener is paused inside Windows (see package
// instant). It reports whether pid should be frozen right now, before it can
// read. It's deliberately conservative: only ordinary programs in a user
// session whose verdict calls for freezing. Everything else is let through
// and handled by the normal audit-log path if it actually reads.
func (e *Engine) DecideInstant(pid uint32, path string) bool {
	e.mu.Lock()
	cfg, cls := e.cfg, e.classifier
	baitID, isBait := e.index[paths.Key(path)]
	e.mu.Unlock()
	if cfg == nil || !isBait || pid == e.SelfPID {
		return false
	}
	image, err := e.Ops.ImagePath(pid)
	if err != nil || image == "" || !e.touchable(pid, image) || !e.Ops.UserSession(pid) {
		return false
	}
	if paths.Same(image, paths.InstalledCLI()) || paths.Same(image, paths.InstalledService()) {
		return false
	}
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == pid {
		return true // `aba test`: always demonstrate the freeze
	}
	if !cfg.InstantFreeze {
		return false
	}
	v := cls.Final(image, pid, baitRef(baitID), e.Ops.Verify(image))
	if v.Ignored || v.DecoyOwner {
		return false
	}
	return config.Has(cfg.ActionsFor(v.Tier, time.Now()), config.ActionFreeze)
}

// HandleOpen raises the alert (and runs the remaining responses) for a reader
// that DecideInstant froze mid-open. frozen is what was suspended.
func (e *Engine) HandleOpen(pid uint32, path string, at time.Time, frozen []uint32) {
	e.handle(&evtlog.ObjectAccess{ProcessID: pid, ObjectName: path, AccessMask: 1, Time: at}, frozen)
}

func baitRef(id string) classify.Bait {
	b := classify.Bait{ID: id}
	if s, ok := baits.ByID(id); ok {
		b.OwnerExes, b.OwnerSigner = s.OwnerExes, s.Signer
	}
	return b
}

// HandleAccess processes one 4663 event.
func (e *Engine) HandleAccess(oa *evtlog.ObjectAccess) { e.handle(oa, nil) }

// handle processes a bait access. preFrozen is non-nil when the reader was
// already frozen mid-open by the instant path, before it could read.
func (e *Engine) handle(oa *evtlog.ObjectAccess, preFrozen []uint32) {
	beforeRead := preFrozen != nil
	received := time.Now()
	baitID, ok := e.IsBait(oa.ObjectName)
	if !ok || oa.ProcessID == e.SelfPID {
		return
	}
	access := "read"
	switch {
	case winsec.AccessMaskIsDelete(oa.AccessMask) && !winsec.AccessMaskIsRead(oa.AccessMask):
		access = "delete"
	case !winsec.AccessMaskIsRead(oa.AccessMask):
		return
	}

	e.mu.Lock()
	cfg, cls, name := e.cfg, e.classifier, e.baitNames[baitID]
	hit := alerts.BaitHit{ID: baitID, Name: name, Path: oa.ObjectName, Access: access, Time: oa.Time}
	if inc := e.incidents[oa.ProcessID]; inc != nil && time.Since(inc.last) < window &&
		(inc.createTime == 0 || inc.createTime == e.Ops.CreateTime(oa.ProcessID)) {
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
	image := oa.ProcessName
	if image == "" || !strings.Contains(image, `\`) {
		if p, err := e.Ops.ImagePath(oa.ProcessID); err == nil {
			image = p
		}
	}
	if paths.Same(image, paths.InstalledCLI()) || paths.Same(image, paths.InstalledService()) {
		return // ABA itself (bait adoption by an admin); its folder is admin-only
	}
	createTime := e.Ops.CreateTime(oa.ProcessID)
	ref := baitRef(baitID)

	test := false
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == oa.ProcessID {
		test = true
	}
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

	// 1-2. Instant verdict, freeze first.
	pre := cls.Prelim(image, oa.ProcessID, ref)
	if pre.Ignored && !beforeRead {
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.ObjectName, image, strings.Join(pre.Reasons, "; "))
		return
	}
	frozen := preFrozen
	var latency time.Duration
	canTouch := e.touchable(oa.ProcessID, image)
	if beforeRead {
		latency = time.Since(oa.Time)
	} else if canTouch && config.Has(actionsFor(pre.Tier), config.ActionFreeze) {
		frozen, _ = e.Ops.SuspendTree(oa.ProcessID)
		latency = time.Since(oa.Time)
	}

	// 3-4. Signature and final verdict.
	sig := authenticode.Result{}
	if image != "" {
		sig = e.Ops.Verify(image)
	}
	v := cls.Final(image, oa.ProcessID, ref, sig)
	if v.Ignored {
		e.Ops.Resume(frozen)
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.ObjectName, image, strings.Join(v.Reasons, "; "))
		return
	}
	acts := actionsFor(v.Tier)
	if v.DecoyOwner {
		acts = nil
	}
	if len(frozen) > 0 && !config.Has(acts, config.ActionFreeze) {
		e.Ops.Resume(frozen)
		frozen = nil
	} else if len(frozen) == 0 && canTouch && config.Has(acts, config.ActionFreeze) {
		frozen, _ = e.Ops.SuspendTree(oa.ProcessID)
		latency = time.Since(oa.Time)
	}

	a := &alerts.Alert{
		ID: alerts.NewID(now), Time: now, Kind: alerts.KindRead, Tier: v.Tier, Verdict: v,
		Learning: learning && len(cfg.Responses[v.Tier]) > 0, Test: test, Status: "open",
		Baits:   []alerts.BaitHit{hit},
		Process: &alerts.Process{PID: oa.ProcessID, Image: image, User: oa.User, Signature: sig},
	}
	a.BeforeRead = beforeRead && len(frozen) > 0
	if access == "delete" {
		a.Kind = alerts.KindDelete
	}
	if test {
		a.Kind = alerts.KindTest
	}
	if config.Has(acts, config.ActionFreeze) {
		if len(frozen) > 0 {
			detail := fmt.Sprintf("%d process(es) frozen", len(frozen))
			if beforeRead {
				detail += " before it read anything"
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
	e.Ops.Forensics(oa.ProcessID, a.Process)

	// 6. Remaining responses.
	var blocked, isolated bool
	var adapters []string
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
		case config.ActionKill:
			if !canTouch {
				a.AddAction(act, fmt.Errorf("refused"), "protected system process")
				continue
			}
			err := e.Ops.KillTree(oa.ProcessID)
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

	e.mu.Lock()
	e.incidents[oa.ProcessID] = &incident{alert: a, createTime: createTime, last: time.Now()}
	for pid, inc := range e.incidents {
		if time.Since(inc.last) > window {
			delete(e.incidents, pid)
		}
	}
	e.mu.Unlock()

	e.Ops.NotifyDesktop(a)
	if test || v.Tier.Rank() >= cfg.PhoneMinTier.Rank() {
		e.Ops.NotifyPhone(a)
	}
	if v.DecoyOwner {
		e.Ops.RetireDecoy(baitID, a.Summary)
	}
	if test {
		e.Ops.KillTree(oa.ProcessID)
		e.Ops.ClearTest()
	}
	e.Ops.Logf("alert %s: %s [%s] actions=%d latency=%dms (delivery %dms)", a.ID, a.Title, a.Tier, len(a.Actions), a.LatencyMS, a.DeliveryMS)
}

func (e *Engine) describe(a *alerts.Alert, v classify.Verdict) {
	exe := a.ExeName()
	what := "read"
	if a.Kind == alerts.KindDelete {
		what = "deleted"
	}
	if a.BeforeRead {
		what = "tried to open"
	}
	switch {
	case a.Test && a.BeforeRead:
		a.Title = "Test detection: " + exe + " was frozen opening a bait, before reading it"
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
	if a.BeforeRead {
		a.Summary = "Frozen while opening the bait, before it could read anything. " + a.Summary
	}
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
