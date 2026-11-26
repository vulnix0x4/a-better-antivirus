package engine

// The host policy: what to do when the genuine browser opens a fake profile
// it doesn't know (a classify.Verdict with Host set).
//
// The browser never opens that folder by itself, so code is running inside
// it. Which browser it is decides what that means:
//
//   - A stealer that wants the cookies a browser guards with its own
//     encryption starts the genuine browser itself: suspended, with no
//     window, and runs its code inside it. Such a copy is nobody's browser:
//     it's frozen, all of it, with whatever started it (case "stop").
//   - The window you're using was started by you and shows itself. Freezing
//     it would lose your work, and it's not where a stealer keeps what it
//     took: ABA cuts the internet of every window of that browser and tells
//     you (case "keep").
//   - One that had already exited when ABA looked was no browser you were
//     using either (case "gone"): there's nothing left to stop.
//
// Each signal is gathered and weighed on its own (hostPlan), so that what a
// real stealer turns out to do can be matched by adjusting one of them.
//
// Only Windows tells ABA these facts (procinfo.Browser); elsewhere the
// verdict stays what classify made it.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/detect"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// adoptWait is how long ABA gives a browser that went through a fake profile
// before cutting its internet: it may be taking the folder as a new profile
// of its own (you added one), and it writes that down a moment later.
const adoptWait = 1500 * time.Millisecond

// hostSeen is what procinfo.Browser said about an opener, gathered once,
// before anything was frozen.
type hostSeen struct {
	inst *procinfo.BrowserInstance
	err  error
	ct   int64
	at   time.Time
}

// hostLock lets one decision about a browser instance run at a time: the
// events of its other processes join the alert it makes.
type hostLock struct {
	mu sync.Mutex
	n  int
}

// What started the browser, as far as the policy is concerned.
type starterKind int

const (
	starterGone      starterKind = iota // exited: nothing to judge or freeze
	starterTrusted                      // judged fine, or beyond ABA's reach (Windows itself, elevated, ABA)
	starterWarn                         // suspicious, not stopped on its own (a signed runtime, a signed program in your folders)
	starterUntrusted                    // it would be stopped itself for reading a bait (unsigned in your folders, a script host)
)

// Whether the instance has a window on your screen.
const (
	visNotChecked = iota
	visUnknown
	visYes
	visNo
)

// hostPlan is the policy's reading of one browser instance.
type hostPlan struct {
	unsupported bool // the system doesn't tell: the verdict stays as it was
	gone        bool // the opener had exited (case "gone")
	inst        *procinfo.BrowserInstance
	starter     starterKind
	starterWhy  string // the starter's own verdict, when it has one
	visible     int
	// stop: it isn't the browser you're using (case "stop"); otherwise
	// it's case "keep".
	stop bool
	// freezeStarter: what started it is frozen with it.
	freezeStarter bool
}

// hostFacts returns procinfo.Browser's facts about pid, gathered once per
// process (the instant path gathers them before it freezes anything, and the
// event-log path then uses those).
func (e *Engine) hostFacts(pid uint32, image string) (*procinfo.BrowserInstance, error) {
	ct := e.Ops.CreateTime(pid)
	e.mu.Lock()
	h, ok := e.hosts[pid]
	e.mu.Unlock()
	if ok && ct != 0 && h.ct == ct && time.Since(h.at) < window {
		return h.inst, h.err
	}
	inst, err := e.Ops.Browser(pid, image)
	if inst == nil && err == nil {
		err = procinfo.ErrGone
	}
	e.mu.Lock()
	for p, x := range e.hosts {
		if time.Since(x.at) > window {
			delete(e.hosts, p)
		}
	}
	e.hosts[pid] = hostSeen{inst: inst, err: err, ct: ct, at: time.Now()}
	e.mu.Unlock()
	return inst, err
}

// judgeStarter says what kind of program started the browser (see
// starterKind), and its own verdict in words.
func (e *Engine) judgeStarter(cls *classify.Classifier, inst *procinfo.BrowserInstance) (starterKind, string) {
	pid, img := inst.Starter, inst.StarterImage
	if inst.StarterGone || pid == 0 {
		return starterGone, ""
	}
	if ct := e.Ops.CreateTime(pid); ct == 0 || (inst.StarterCreate != 0 && ct != inst.StarterCreate) {
		return starterGone, "" // exited since, or its PID was reused
	}
	if !strings.ContainsAny(img, `\/`) || !e.touchable(pid, img) || !e.Ops.UserSession(pid) || e.Ops.Elevated(pid) || e.Ops.IsSelf(img) {
		return starterTrusted, ""
	}
	v := cls.Final(img, pid, classify.Bait{}, e.Ops.Verify(img))
	why := ""
	if len(v.Reasons) > 0 {
		why = v.Reasons[0]
	}
	switch {
	case v.Ignored || v.Tier == config.TierInfo:
		return starterTrusted, why
	case v.Tier == config.TierCritical:
		return starterUntrusted, why
	}
	return starterWarn, why
}

// hostPlanFor reads the browser instance pid belongs to. checkWindows: ask
// whether it has a window on your screen (it takes up to a second, so the
// instant path doesn't: it decides only what the quick facts settle).
func (e *Engine) hostPlanFor(cls *classify.Classifier, pid uint32, image string, checkWindows bool) hostPlan {
	inst, err := e.hostFacts(pid, image)
	switch {
	case errors.Is(err, procinfo.ErrUnsupported):
		return hostPlan{unsupported: true}
	case err != nil || inst == nil:
		return hostPlan{gone: true}
	}
	p := hostPlan{inst: inst, visible: visNotChecked}
	p.starter, p.starterWhy = e.judgeStarter(cls, inst)
	quick := inst.CreatedSuspended || len(inst.Hidden) > 0 || p.starter == starterUntrusted
	if !quick && checkWindows {
		p.visible = visUnknown
		if vis, known := e.Ops.VisibleWindow(inst.PIDs); known {
			p.visible = visNo
			if vis {
				p.visible = visYes
			}
		}
	}
	// Switches that start it with no window count unless it does show one:
	// a browser you run in the background and then opened a window in is
	// still yours.
	flagged := len(inst.Flags) > 0 && (p.visible == visNo || p.visible == visUnknown)
	p.stop = quick || p.visible == visNo || flagged
	// Whatever created a browser suspended that then went through a fake
	// profile is the injector, even a signed runtime (python.exe).
	p.freezeStarter = p.stop && (p.starter == starterUntrusted || (inst.CreatedSuspended && p.starter == starterWarn))
	return p
}

// starterName names what started the browser, for the alert.
func (p hostPlan) starterName() string {
	if p.inst == nil || p.starter == starterGone {
		return "a program that has since exited"
	}
	return procinfo.BaseName(p.inst.StarterImage)
}

// stopVerdict is the verdict for a browser that isn't the one you're using.
func (p hostPlan) stopVerdict(v classify.Verdict) classify.Verdict {
	inst := p.inst
	name := alerts.BrowserName(inst.Image)
	how := "was started"
	switch {
	case inst.CreatedSuspended:
		how += " suspended"
	case len(inst.Hidden) > 0:
		how += " hidden"
	}
	how += " by " + p.starterName()
	if inst.CreatedSuspended {
		how += " and never ran as a browser"
	}
	parts := []string{how}
	if p.visible == visNo {
		parts = append(parts, "has no window on your screen")
	}
	why := fmt.Sprintf("%s %s, then went through a fake profile only a stealer would open: that's a stealer running its own code inside a genuine %s, to get at the passwords and cookies it protects",
		name, strings.Join(parts, " and "), name)
	reasons := []string{why}
	if inst.CreatedSuspended {
		reasons = append(reasons, "created suspended: its first thread never ran, so it never got to be a browser; code was put into it instead")
	}
	for _, h := range inst.Hidden {
		reasons = append(reasons, "started hidden: "+h)
	}
	if len(inst.Flags) > 0 && p.visible != visYes {
		reasons = append(reasons, "started with "+strings.Join(inst.Flags, ", "))
	}
	if p.starter != starterGone && p.inst.StarterImage != "" {
		s := "started by " + p.inst.StarterImage
		if p.starterWhy != "" {
			s += ": " + p.starterWhy
		}
		reasons = append(reasons, s)
	}
	froze := fmt.Sprintf("ABA froze that %s, all of it (its main process and everything it started)", name)
	if p.freezeStarter {
		froze += ", and what started it"
	}
	reasons = append(reasons, froze)
	return classify.Verdict{Tier: config.TierCritical, Host: true, Swept: v.Swept, Reasons: append(reasons, v.Reasons...)}
}

// which names the browser by what gave it away, for an alert's title: "a
// Chrome started suspended by ghost.exe", "an Edge with no window on your
// screen".
func (p hostPlan) which() string {
	inst := p.inst
	name := alerts.BrowserName(inst.Image)
	a := "a "
	if strings.ContainsAny(strings.ToLower(name[:1]), "aeiou") {
		a = "an "
	}
	switch {
	case inst.CreatedSuspended:
		return a + name + " started suspended by " + p.starterName()
	case len(inst.Hidden) > 0:
		return a + name + " started hidden by " + p.starterName()
	case p.starter == starterUntrusted:
		return a + name + " started by " + p.starterName()
	case p.visible == visNo:
		return a + name + " with no window on your screen"
	case len(inst.Flags) > 0:
		flag, _, _ := strings.Cut(inst.Flags[0], " ")
		return a + name + " started with " + flag
	}
	return a + name + " that isn't the one you're using"
}

// keepVerdict is the verdict for the browser you're using: critical, but it
// keeps running (its internet is cut instead, as configured).
func (p hostPlan) keepVerdict(v classify.Verdict) classify.Verdict {
	name := alerts.BrowserName(p.inst.Image)
	why := fmt.Sprintf("%s opened a fake profile that only a stealer would open: something is running inside the %s you're using (an add-on, or code a stealer put into it)", name, name)
	reasons := []string{why}
	switch p.visible {
	case visYes:
		reasons = append(reasons, "it has a window on your screen, and nothing about how it was started is unusual: it's the browser you're using, so ABA doesn't freeze it (you'd lose your work)")
	case visUnknown:
		reasons = append(reasons, "ABA couldn't check whether it has a window on your screen, and nothing about how it was started is unusual: it's treated as the browser you're using, so it isn't frozen")
	}
	if p.starter != starterGone && p.inst.StarterImage != "" {
		reasons = append(reasons, "started by "+p.inst.StarterImage)
	}
	return classify.Verdict{Tier: config.TierCritical, Host: true, KeepRunning: true, Swept: v.Swept, Reasons: append(reasons, v.Reasons...)}
}

// goneVerdict is the verdict for a browser that had exited before ABA could
// look at it.
func goneVerdict(v classify.Verdict, image string) classify.Verdict {
	name := alerts.BrowserName(image)
	why := fmt.Sprintf("%s opened a fake profile that only a stealer would open, and had already exited before ABA could look at it: the %s you're using doesn't come and go in a moment, a stealer running its code inside a throwaway copy of it does",
		name, name)
	return classify.Verdict{Tier: config.TierCritical, Host: true, Swept: v.Swept, Reasons: append([]string{why}, v.Reasons...)}
}

// starterFreezable reports whether the starter at pid (running image) may be
// frozen with the browser it started (see hostPlan.freezeStarter): never
// Windows itself, ABA, an elevated program or one in another session.
func (e *Engine) starterFreezable(cls *classify.Classifier, p hostPlan, pid uint32, image string) bool {
	if !p.freezeStarter || p.inst == nil || pid != p.inst.Starter || image == "" {
		return false
	}
	if !e.touchable(pid, image) || !e.Ops.UserSession(pid) || e.Ops.Elevated(pid) || e.Ops.IsSelf(image) {
		return false
	}
	return p.starter == starterUntrusted || p.starter == starterWarn
}

// lockHost waits for any other decision about the browser instance to end,
// and returns the function that ends this one.
func (e *Engine) lockHost(inst *procinfo.BrowserInstance) func() {
	key := fmt.Sprintf("%d-%x", inst.Main, uint64(inst.MainCreate))
	e.mu.Lock()
	l := e.hostLocks[key]
	if l == nil {
		l = &hostLock{}
		e.hostLocks[key] = l
	}
	l.n++
	e.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		e.mu.Lock()
		if l.n--; l.n == 0 {
			delete(e.hostLocks, key)
		}
		e.mu.Unlock()
	}
}

// errReadOnly ends a look at the state that has nothing to write.
var errReadOnly = errors.New("read only")

// undone reports whether what ABA did about alert a has all been undone
// since (`aba resume`, `aba release`, `aba trust`): then the case is closed,
// and what that program does next is a new alert, with a new response, not
// a line added to one nobody is looking at any more. An alert that did
// nothing that stays in place (alert only) is never undone.
func (e *Engine) undone(a *alerts.Alert) bool {
	if !a.Did(config.ActionFreeze) && !a.Did(config.ActionBlockProgram) && !a.Did(config.ActionIsolate) && !a.Did(config.ActionDisableAdapters) {
		return false
	}
	still := false
	e.Ops.UpdateState(func(st *config.State) error {
		for _, f := range st.Frozen {
			still = still || f.AlertID == a.ID
		}
		for _, b := range st.Blocked {
			still = still || b.AlertID == a.ID
		}
		still = still || (st.Isolation != nil && st.Isolation.AlertID == a.ID)
		return errReadOnly
	})
	return !still
}

// oldNews reports whether an access made at time t was made before alert a
// was: word of it came late (the Security log can deliver seconds after the
// fact), so it's part of what a is about, however a has been answered since.
// Only what a program does after you undid ABA's response is a new case.
func oldNews(t time.Time, a *alerts.Alert) bool {
	return !t.IsZero() && t.Before(a.Time)
}

// joinHost adds hit to the alert already made about the browser instance,
// if there is one: one alert, and one freeze, per instance. pid is the
// process that made this access; it joins the incident too.
func (e *Engine) joinHost(inst *procinfo.BrowserInstance, pid uint32, hit alerts.BaitHit) bool {
	e.mu.Lock()
	inc := e.incidents[inst.Main]
	if inc == nil || !inc.alert.Verdict.Host || time.Since(inc.last) >= window || (inc.createTime != 0 && inc.createTime != inst.MainCreate) {
		e.mu.Unlock()
		return false
	}
	a := inc.alert
	e.mu.Unlock()
	if !oldNews(hit.Time, a) && e.undone(a) {
		e.closeIncident(a)
		return false
	}
	e.mu.Lock()
	if e.incidents[inst.Main] != inc {
		e.mu.Unlock()
		return false
	}
	inc.last = time.Now()
	if pid != inst.Main {
		e.incidents[pid] = &incident{alert: inc.alert, createTime: e.Ops.CreateTime(pid), last: inc.last}
	}
	cp, changed := e.addHit(inc.alert, hit)
	e.mu.Unlock()
	if changed {
		e.Ops.SaveAlert(cp)
	}
	return true
}

// closeIncident forgets every process's incident that is alert a.
func (e *Engine) closeIncident(a *alerts.Alert) {
	e.mu.Lock()
	for p, inc := range e.incidents {
		if inc.alert == a {
			delete(e.incidents, p)
		}
	}
	e.mu.Unlock()
}

// addHit adds a bait hit to an alert (unless it's there already) and returns
// a copy to save. Called with e.mu held.
func (e *Engine) addHit(a *alerts.Alert, hit alerts.BaitHit) (*alerts.Alert, bool) {
	for _, h := range a.Baits {
		if strings.EqualFold(h.Path, hit.Path) && h.Access == hit.Access {
			return nil, false
		}
	}
	a.Baits = append(a.Baits, hit)
	cp := *a // the autopsy may be filling the alert in meanwhile (see autopsy)
	cp.Baits = append([]alerts.BaitHit(nil), a.Baits...)
	return &cp, true
}

// takeWait is how long ABA watches the browser you're using, after it went
// to delete or overwrite a fake profile's files, for it to finish making that
// folder a profile of its own (you added a profile, and it reached that
// folder's name). It wipes the folder, makes a real profile in it and writes
// that down in its list of profiles seconds later (Brave, in the VM: the
// files deleted within 0.24 s, the folder made anew at 1.3 s, listed at
// 10.1 s).
const takeWait = 15 * time.Second

// stillUnadopted looks again, a moment later, whether the browser has taken
// the fake profile as its own after all (you added a profile, and it reached
// that folder's name): then it's the genuine app at work on its own data. A
// browser that went to delete or overwrite the fake's files (destructive) is
// most likely doing just that, so it's given longer, and its making the
// folder a real profile on disk counts as soon as it's seen.
func (e *Engine) stillUnadopted(baitID string, destructive bool) bool {
	e.mu.Lock()
	wait, long := e.adoptWait, e.takeWait
	e.mu.Unlock()
	if !destructive {
		if wait > 0 {
			time.Sleep(wait)
		}
		return e.baitRef(baitID).Unadopted
	}
	deadline := time.Now().Add(long)
	for {
		if e.takenOver(baitID) {
			return false
		}
		if !time.Now().Before(deadline) {
			return true
		}
		time.Sleep(min(300*time.Millisecond, time.Until(deadline)+time.Millisecond))
	}
}

// takenOver: the real browser has made the fake profile's folder a profile
// of its own, listed or (so far) only on disk.
func (e *Engine) takenOver(baitID string) bool {
	s, ok := baits.ByID(baitID)
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()
	return ok && cfg != nil && s.Inside != nil && (e.adopted(s, cfg.User) || baits.TakenOver(s, cfg.User))
}

// hostRead reports, before the reader is classified, whether oa is the
// genuine browser (its own program, in its own folder, signed by its maker)
// opening a fake profile inside it that it doesn't know: what classify
// calls a Host verdict. Such a read is settled by the host policy, about
// that browser alone, and never counts toward a sweep: not as the read that
// completes one, and not as an earlier one that a later read completes.
func (e *Engine) hostRead(oa *detect.Access, baitID string) bool {
	if !embedded(baitID) {
		return false
	}
	image := oa.Image
	if live, err := e.Ops.ImagePath(oa.PID); err == nil && live != "" {
		image = live
	}
	e.mu.Lock()
	cls := e.classifier
	e.mu.Unlock()
	ref := e.baitRef(baitID)
	if cls == nil || !ref.Unadopted || ref.OwnerSigner == "" || !cls.OwnerCandidate(image, ref) {
		return false
	}
	sig := e.Ops.Verify(image)
	return sig.Valid && strings.Contains(strings.ToLower(sig.Signer), strings.ToLower(ref.OwnerSigner))
}

// embedded: the bait is a fake profile inside a real browser.
func embedded(baitID string) bool {
	s, ok := baits.ByID(baitID)
	return ok && s.Inside != nil
}

// tookVerdict is the verdict for the real browser taking a fake profile's
// folder as a profile of its own: nothing wrong, and ABA puts a new fake
// profile under another name (see the service's RetireDecoy).
func (e *Engine) tookVerdict(image, baitID string) classify.Verdict {
	name := alerts.BrowserName(image)
	folder := "its folder"
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()
	if cfg != nil {
		folder = baits.ProfileFolder(cfg.User, baitID)
	}
	why := fmt.Sprintf("%s used the name of ABA's fake profile (%s) for a profile you added, and made that folder a real profile of its own. ABA puts a new fake profile next to your real ones, under another name: nothing for you to do. (If you didn't just add a profile in %s, something else made it take that folder.)",
		name, folder, name)
	return classify.Verdict{Tier: config.TierInfo, DecoyOwner: true, Host: true, Reasons: []string{why}}
}

// ClaimAll claims the processes the instant path froze for a browser
// instance: the event log's reports of what they did join that alert,
// instead of freezing them again (suspensions stack).
func (e *Engine) ClaimAll(pids []uint32) {
	for _, p := range pids {
		e.claim(p)
	}
}

// InstantRoots says what the service is to freeze (each with what it
// started) for an opener that DecideInstantOpWhy decided to freeze: the
// opener, or for a browser that isn't the one you're using, the whole
// instance from its main process, and what started it (instance true: then
// claim every process frozen, see ClaimAll).
func (e *Engine) InstantRoots(pid uint32) (roots []uint32, instance bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.roots[pid]; ok {
		delete(e.roots, pid)
		return r, true
	}
	return []uint32{pid}, false
}

func (e *Engine) setRoots(pid uint32, roots []uint32) {
	e.mu.Lock()
	if len(e.roots) > 256 {
		e.roots = map[uint32][]uint32{}
	}
	e.roots[pid] = roots
	e.mu.Unlock()
}

// HostSuspect returns which of pids (programs paused inside an open of path)
// is a genuine browser, created suspended and never run, going through the
// fake profile at path: the one thing a stealer running code inside a
// browser it started looks like. It's decided while the open is still
// paused, so the code never gets a byte of the file. 0 if none, or more than
// one.
func (e *Engine) HostSuspect(path string, pids []uint32) uint32 {
	e.mu.Lock()
	baitID, ok := e.index[paths.Key(path)]
	cls := e.classifier
	e.mu.Unlock()
	if !ok || cls == nil {
		return 0
	}
	if s, ok := baits.ByID(baitID); !ok || s.Inside == nil {
		return 0
	}
	ref := e.baitRef(baitID)
	if !ref.Unadopted {
		return 0
	}
	var hit uint32
	n := 0
	for _, pid := range pids {
		if pid == e.SelfPID || pid <= 4 {
			continue
		}
		image, err := e.Ops.ImagePath(pid)
		if err != nil || !cls.OwnerCandidate(image, ref) {
			continue
		}
		if inst, err := e.hostFacts(pid, image); err == nil && inst != nil && inst.CreatedSuspended {
			hit = pid
			n++
		}
	}
	if n != 1 {
		return 0
	}
	return hit
}

// ownApps says which of pids are a genuine browser (its own program, in its
// own folder, signed by its maker), and whose data that is (pid -> the store
// ID, which is the bait's): see autopsy.Case.Own. Not for a browser a
// stealer started: what that copy opened, it opened for the stealer.
func (e *Engine) ownApps(cls *classify.Classifier, pids []uint32) map[uint32]string {
	out := map[uint32]string{}
	images := map[uint32]string{}
	for _, p := range pids {
		if img, err := e.Ops.ImagePath(p); err == nil && img != "" {
			images[p] = img
		}
	}
	for _, s := range baits.Catalog {
		if s.Inside == nil {
			continue
		}
		ref := e.baitRef(s.ID)
		for p, img := range images {
			if _, done := out[p]; done || ref.OwnerSigner == "" || !cls.OwnerCandidate(img, ref) {
				continue
			}
			if sig := e.Ops.Verify(img); sig.Valid && strings.Contains(strings.ToLower(sig.Signer), strings.ToLower(ref.OwnerSigner)) {
				out[p] = s.ID
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sameImage reports whether a and b are the same program file.
func sameImage(a, b string) bool {
	return a != "" && b != "" && (paths.Same(a, b) || strings.EqualFold(filepath.Clean(a), filepath.Clean(b)))
}
