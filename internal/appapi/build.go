package appapi

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/autopsy"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/trust"
)

// Source is everything the screens are built from: read from disk by Load
// (as an administrator), or made up by the tests.
type Source struct {
	Version string
	Now     time.Time
	Config  *config.Config
	State   *config.State
	// Alerts are every alert, newest first.
	Alerts         []*alerts.Alert
	ServiceRunning bool
	// PhoneVia is the kind of phone alerts set up ("" when off).
	PhoneVia string
	// ClipboardSupported and MinersSupported: the traps exist on this system.
	ClipboardSupported bool
	MinersSupported    bool
	// Updatable: a release build. Newer reports whether tag is newer than
	// the running version (update.Newer).
	Updatable bool
	Newer     func(current, tag string) bool
}

// staleAfter: a service that hasn't checked in for this long isn't running
// as it should (it writes its heartbeat every minute or so).
const staleAfter = 5 * time.Minute

func (s *Source) cfg() *config.Config {
	if s.Config == nil {
		return config.Default()
	}
	return s.Config
}

func (s *Source) state() *config.State {
	if s.State == nil {
		return config.NewState()
	}
	return s.State
}

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nonNil[T any](x []T) []T {
	if x == nil {
		return []T{}
	}
	return x
}

// ---- Home ----

// Snapshot builds the Home screen.
func (s *Source) Snapshot() *Snapshot {
	cfg, st := s.cfg(), s.state()
	out := &Snapshot{Schema: Schema, Mode: "full", Version: s.Version, Now: s.Now, QuietDays: -1,
		Absent: []string{AbsentTouchChart}}
	out.Baits = s.baitsSummary()
	out.Preset = presetView(cfg)
	out.Traps = Traps{Baits: out.Baits.Total, Instant: cfg.InstantFreeze, Recorder: !cfg.NoRecorder,
		Clipboard: Switchable{On: cfg.ClipboardBait, Supported: s.ClipboardSupported},
		Miners:    Switchable{On: cfg.MinerTrap, Supported: s.MinersSupported}}
	out.Update = s.updateView()
	out.Waiting, out.RecentQuiet, out.Frozen = []AlertRow{}, []AlertRow{}, []FrozenItem{}
	for _, f := range st.Frozen {
		out.Frozen = append(out.Frozen, FrozenItem{AlertID: f.AlertID, Program: base(f.Image), PID: f.PID, Since: f.Since})
	}
	for _, a := range s.Alerts {
		row := s.row(a)
		switch {
		case a.Status == "open" && len(s.buttons(a)) > 0:
			out.Waiting = append(out.Waiting, row)
		case row.Outcome == OutcomeNoted && len(out.RecentQuiet) < 10:
			out.RecentQuiet = append(out.RecentQuiet, row)
		}
		if out.LastCatch == nil && caught(a, row.Outcome) {
			t := a.Time
			out.LastCatch = &t
		}
	}
	since := cfg.InstalledAt
	if out.LastCatch != nil {
		since = *out.LastCatch
	}
	if !since.IsZero() && !s.Now.Before(since) {
		out.QuietDays = int(s.Now.Sub(since) / (24 * time.Hour))
	}
	out.Protection = s.protection(out.Baits, len(out.Waiting) > 0)
	return out
}

// caught: an alert about a program that ABA stopped, or that it rated
// critical (Alert only stops nothing). Not tests, not quiet touches, not
// what you said was yours.
func caught(a *alerts.Alert, outcome string) bool {
	if a.Test || a.Process == nil {
		return false
	}
	switch outcome {
	case OutcomeNoted, OutcomeTrusted:
		return false
	case OutcomeFrozen, OutcomeCutOff, OutcomeKilled, OutcomeStopped:
		return true
	}
	return a.Tier == config.TierCritical
}

func (s *Source) protection(b BaitsSummary, waiting bool) Protection {
	cfg, st := s.cfg(), s.state()
	p := Protection{ServiceRunning: s.ServiceRunning, Heartbeat: tp(st.Heartbeat), Problems: []string{},
		Health: healthItems(st.Health), Learning: cfg.Learning(s.Now)}
	if p.Learning {
		p.LearningUntil = tp(cfg.LearningUntil)
	}
	if st.Isolation != nil {
		p.IsolatedSince = tp(st.Isolation.Since)
	}
	if !s.ServiceRunning {
		p.Problems = append(p.Problems, "The ABA service isn't running.")
	} else if st.Heartbeat.IsZero() || s.Now.Sub(st.Heartbeat) > staleAfter {
		p.Problems = append(p.Problems, "The ABA service hasn't checked in for a while.")
	}
	stopped := len(p.Problems) > 0
	if n := b.Total - b.Healthy; n == 1 {
		p.Problems = append(p.Problems, "1 bait isn't in place.")
	} else if n > 1 {
		p.Problems = append(p.Problems, fmt.Sprintf("%d baits aren't in place.", n))
	}
	if b.Total == 0 {
		p.Problems = append(p.Problems, "No baits are planted.")
	}
	for _, h := range st.Health {
		if !h.OK {
			l := h.Name
			if h.Detail != "" {
				l += ": " + h.Detail
			}
			p.Problems = append(p.Problems, l)
		}
	}
	cutOff := false
	for _, a := range s.Alerts {
		if a.Status == "open" && st.IsBlocked(imageOf(a)) {
			cutOff = true
			break
		}
	}
	switch {
	case stopped:
		p.State, p.Headline = "stopped", "Not running"
	case st.Isolation != nil:
		p.State, p.Headline = "isolated", "Offline: something was caught"
	case len(st.Frozen) > 0 || (waiting && cutOff):
		p.State, p.Headline = "frozen", "Something is frozen"
	case len(p.Problems) > 0:
		p.State, p.Headline = "attention", "Needs a look"
	default:
		p.State, p.Headline = "protected", "Protected"
	}
	return p
}

func imageOf(a *alerts.Alert) string {
	if a.Process == nil {
		return ""
	}
	return a.Process.Image
}

func healthItems(in []config.HealthItem) []HealthItem {
	out := []HealthItem{}
	for _, h := range in {
		out = append(out, HealthItem{Name: h.Name, OK: h.OK, Detail: h.Detail})
	}
	return out
}

func (s *Source) baitsSummary() BaitsSummary {
	st := s.state()
	out := BaitsSummary{ByKind: []KindCount{}, Tags: []BaitTag{}}
	counts := map[string]*KindCount{}
	var cats []string
	for _, id := range s.baitIDs() {
		bs := st.Baits[id]
		info := baitInfo(id, bs.Name)
		h := health(bs.Status)
		out.Total++
		k := counts[info.Category]
		if k == nil {
			k = &KindCount{Category: info.Category}
			counts[info.Category] = k
			cats = append(cats, info.Category)
		}
		k.Total++
		if h == "ok" {
			out.Healthy++
			k.Healthy++
		}
		if t := bs.LastCheck; !t.IsZero() && (out.LastCheck == nil || t.After(*out.LastCheck)) {
			out.LastCheck = tp(t)
		}
		out.Tags = append(out.Tags, BaitTag{ID: id, Label: info.Label, Icon: info.Icon, Health: h})
	}
	sort.SliceStable(cats, func(i, j int) bool { return categoryRank(cats[i]) < categoryRank(cats[j]) })
	for _, c := range cats {
		out.ByKind = append(out.ByKind, *counts[c])
	}
	return out
}

// baitIDs are the planted (not retired) baits, most tempting first (the
// catalog's order of interest), then by ID.
func (s *Source) baitIDs() []string {
	var ids []string
	for id, bs := range s.state().Baits {
		if bs != nil && bs.Status != "retired" {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		ri, rj := baitInfo(ids[i], "").rank, baitInfo(ids[j], "").rank
		if ri != rj {
			return ri < rj
		}
		return ids[i] < ids[j]
	})
	return ids
}

// health is a bait's state.Status as the app shows it.
func health(status string) string {
	switch status {
	case "ok":
		return "ok"
	case "missing":
		return "missing"
	}
	return "error"
}

var presetWords = map[string]PresetOption{
	"alert":    {ID: "alert", Name: "Alert only", Says: "Tells you. Stops nothing.", Does: []string{"alert"}},
	"balanced": {ID: "balanced", Name: "Balanced", Says: "Freezes it and cuts its internet.", Does: []string{"alert", "freeze", "cut"}},
	"strict":   {ID: "strict", Name: "Strict", Says: "Also takes the whole PC offline.", Does: []string{"alert", "freeze", "cut", "offline"}},
}

func presetView(cfg *config.Config) PresetView {
	switch cfg.Preset {
	case "alert":
		return PresetView{ID: "alert", Name: "Alert only", Says: "On a catch: tell you, stop nothing"}
	case "balanced":
		return PresetView{ID: "balanced", Name: "Balanced", Says: "On a catch: freeze it, cut its internet"}
	case "strict":
		return PresetView{ID: "strict", Name: "Strict", Says: "On a catch: freeze it, take the PC offline"}
	}
	return PresetView{ID: "custom", Name: "Custom", Says: "Your own responses (set with aba configure)"}
}

func (s *Source) updateView() UpdateView {
	cfg, st := s.cfg(), s.state()
	u := UpdateView{Version: s.Version, Auto: cfg.AutoUpdate, Updatable: s.Updatable}
	if st.Update != nil {
		u.Latest, u.LastResult = st.Update.Latest, st.Update.LastResult
		u.LastCheck, u.UpdatedAt = tp(st.Update.LastCheck), tp(st.Update.UpdatedAt)
		if u.Latest != "" && s.Updatable && s.Newer != nil {
			u.Available = s.Newer(s.Version, u.Latest)
		}
	}
	return u
}

// ---- History ----

// History builds the History screen.
func (s *Source) History() *History {
	out := &History{Schema: Schema, Items: []AlertRow{}, Absent: []string{}}
	for _, a := range s.Alerts {
		r := s.row(a)
		out.Items = append(out.Items, r)
		c := &out.Counts
		c.Total++
		switch {
		case a.Test:
			c.Tests++
		case r.Outcome == OutcomeNoted:
			c.Quiet++
		case r.Outcome == OutcomeTrusted:
			c.Trusted++
		}
		if r.Outcome == OutcomeKilled {
			c.Killed++
		}
		if r.Outcome == OutcomeFrozen {
			c.Frozen++
		}
		if caught(a, r.Outcome) {
			c.Caught++
		}
	}
	return out
}

func (s *Source) row(a *alerts.Alert) AlertRow {
	r := AlertRow{ID: a.ID, ShortID: alerts.ShortID(a.ID), Time: a.Time, Category: category(a), Tier: string(a.Tier),
		Outcome: s.outcome(a), Title: a.Title, Test: a.Test}
	if a.Process != nil {
		r.Program = exeName(a)
	}
	if len(a.Baits) > 0 {
		r.Bait = baitInfo(a.Baits[0].ID, a.Baits[0].Name).Label
	}
	r.Line = rowLine(a, r)
	switch {
	case a.Test:
		r.Icon = "test"
	case r.Outcome == OutcomeTrusted:
		r.Icon = "trusted"
	case r.Outcome == OutcomeNoted:
		r.Icon = "quiet"
	case r.Category == CategoryMiner, r.Category == CategoryClipper, r.Category == CategoryStealer:
		r.Icon = r.Category
	default:
		r.Icon = "system"
	}
	return r
}

// rowLine is the row's one short sentence.
func rowLine(a *alerts.Alert, r AlertRow) string {
	switch {
	case a.Test:
		return "The safe test. Everything worked."
	case r.Category == CategoryMiner:
		return "Hidden miner. Walked into the fake pool."
	case r.Category == CategoryClipper:
		return "Clipper. Swapped an address you copied."
	case r.Outcome == OutcomeNoted:
		return "Looked legitimate. Noted quietly."
	case r.Outcome == OutcomeTrusted:
		if r.Bait != "" {
			return "Yours. It read the " + r.Bait + " bait."
		}
		return "Yours."
	case r.Category == CategoryStealer:
		verb := "Opened"
		if len(a.Baits) > 0 {
			switch a.Baits[0].Access {
			case "delete":
				verb = "Deleted"
			case "write":
				verb = "Changed"
			}
		}
		what := "a bait"
		if r.Bait != "" {
			what = "the " + r.Bait + " bait"
		}
		if a.Tier == config.TierCritical {
			return "Stealer. " + verb + " " + what + "."
		}
		return verb + " " + what + "."
	}
	if a.Summary != "" {
		return a.Summary
	}
	return a.Title
}

func category(a *alerts.Alert) string {
	switch {
	case a.Test:
		return CategoryTest
	case a.Kind == alerts.KindMiner:
		return CategoryMiner
	case a.Kind == alerts.KindClipper:
		return CategoryClipper
	case a.Kind == alerts.KindTamper:
		return CategoryTamper
	case a.Process != nil && (a.Kind == alerts.KindRead || a.Kind == alerts.KindWrite || a.Kind == alerts.KindDelete):
		return CategoryStealer
	}
	return CategoryBait
}

// outcome is how an alert ended, or stands.
func (s *Source) outcome(a *alerts.Alert) string {
	st := s.state()
	note := strings.ToLower(a.Note)
	switch {
	case a.Status == alerts.StatusNoted:
		return OutcomeNoted
	case a.Did(config.ActionKill) || note == "killed":
		return OutcomeKilled
	case strings.Contains(note, "trusted this program"):
		return OutcomeTrusted
	case a.Status == "resolved" && (strings.HasPrefix(note, "let run again") || strings.HasPrefix(note, "you gave") ||
		strings.Contains(note, "said it was yours")):
		return OutcomeResumed
	case st.IsFrozen(a.ID):
		return OutcomeFrozen
	case a.Status == "open" && blockedFor(st, a.ID):
		return OutcomeCutOff
	case a.Did(config.ActionFreeze) || a.Did(config.ActionBlockProgram) || a.Did(config.ActionIsolate):
		return OutcomeStopped
	case a.Status == "resolved":
		return OutcomeAnswered
	}
	return OutcomeAlerted
}

func blockedFor(st *config.State, id string) bool {
	for _, b := range st.Blocked {
		if b.AlertID == id {
			return true
		}
	}
	return false
}

// buttons are the answers an alert takes (the popup's choices).
func (s *Source) buttons(a *alerts.Alert) []string {
	out := []string{}
	if a.Status != "open" || a.Test || a.Process == nil {
		return out
	}
	st := s.state()
	held := st.IsFrozen(a.ID) || blockedFor(st, a.ID)
	isolated := st.Isolation != nil && st.Isolation.AlertID == a.ID
	switch {
	case a.Verdict.KeepRunning:
		if held {
			out = append(out, ButtonResume)
		}
	case a.Verdict.Host:
		if held {
			out = append(out, ButtonKill, ButtonResume)
		}
	case a.Kind == alerts.KindMiner:
		if held {
			out = append(out, ButtonKill, ButtonResume)
		}
	case a.Kind == alerts.KindRead || a.Kind == alerts.KindClipper || a.Kind == alerts.KindWrite || a.Kind == alerts.KindDelete:
		if a.Process.Image == "" {
			break
		}
		if held {
			out = append(out, ButtonKill, ButtonResume)
		}
		out = append(out, ButtonTrust)
	}
	if isolated {
		out = append(out, ButtonRelease)
	}
	return out
}

// ---- Caught + Full report ----

// Alert builds the Caught screen and the Full report of alert a.
func (s *Source) Alert(a *alerts.Alert) *Alert {
	st := s.state()
	r := s.row(a)
	out := &Alert{Schema: Schema, ID: a.ID, ShortID: r.ShortID, Time: a.Time, Category: r.Category, Tier: string(a.Tier),
		Outcome: r.Outcome, Status: a.Status, Note: a.Note, Title: a.Title, Summary: a.Summary, Test: a.Test,
		Learning: a.Learning, Instant: a.Instant, LatencyMS: a.LatencyMS, Baits: []BaitHit{},
		Reasons: nonNil(a.Verdict.Reasons), Did: []Done{}, Buttons: s.buttons(a), Checklist: []string{},
		Absent: []string{AbsentChecklistTicks, AbsentWebhookShutdown, AbsentBlockedSends, AbsentProgramSize}}
	for _, f := range st.Frozen {
		if f.AlertID == a.ID {
			out.FrozenNow = true
			if out.FrozenSince == nil || f.Since.Before(*out.FrozenSince) {
				out.FrozenSince = tp(f.Since)
			}
		}
	}
	out.CutOff = blockedFor(st, a.ID)
	out.Isolated = st.Isolation != nil && st.Isolation.AlertID == a.ID
	for _, b := range a.Baits {
		info := baitInfo(b.ID, b.Name)
		out.Baits = append(out.Baits, BaitHit{ID: b.ID, Label: info.Label, Icon: info.Icon, Name: b.Name, Path: b.Path, Access: b.Access, Time: b.Time})
	}
	for _, d := range a.Actions {
		w := config.Action(d.Action).Done(d.Detail)
		if !d.OK {
			w = "Couldn't " + config.Action(d.Action).Verb() + ": " + d.Detail
		}
		out.Did = append(out.Did, Done{Action: string(d.Action), OK: d.OK, Words: w, Time: d.Time})
	}
	if a.Process != nil {
		out.Program = program(a)
		out.TrustForGood = OneClickTrust(a)
	}
	if a.Tier == config.TierCritical && !a.Test && a.Process != nil {
		out.Checklist = alerts.Checklist(a)
	}
	if a.Mine != nil {
		out.Mine = &Mine{Pool: a.Mine.Pool, Wallet: a.Mine.Wallet, Agent: a.Mine.Agent}
	}
	if a.Kind == alerts.KindClipper && a.Autopsy != nil && a.Autopsy.AttackerWallet != "" {
		n := a.Autopsy.WalletNote
		if n == "" {
			n = "what it swapped in for yours"
		}
		out.Clipper = &Clipper{Wallet: a.Autopsy.AttackerWallet, Note: n}
	}
	if a.Autopsy != nil {
		out.Report = report(a, st)
	}
	return out
}

func program(a *alerts.Alert) *Program {
	p := a.Process
	out := &Program{Name: exeName(a), Path: p.Image, PID: p.PID, Signed: p.Signature.Valid, Signer: p.Signature.Signer,
		Signature: signatureWords(p), SHA256: p.SHA256, Folder: folderWords(p.Image), CommandLine: p.CommandLine,
		User: p.User, Exited: p.Exited}
	if !p.Signature.Valid {
		out.Signer = ""
	}
	if len(p.Parents) > 0 {
		par := p.Parents[0]
		if par.Exited || par.Image == "" {
			out.StartedBy = "a program that has ended since"
		} else {
			out.StartedBy = base(par.Image)
		}
	}
	if o := p.Origin; o != nil {
		l := "Downloaded from " + o.Where()
		if o.File != "" && !strings.EqualFold(o.File, p.Image) {
			l += " (" + base(o.File) + ")"
		}
		out.Origin = &Origin{URL: o.URL, Referrer: o.Referrer, Via: o.Via, Line: l}
	}
	return out
}

func signatureWords(p *alerts.Process) string {
	sig := p.Signature
	switch {
	case sig.Valid:
		return "Signed by " + sig.Signer + "."
	case sig.Signed:
		e := sig.Error
		if e == "" {
			e = "it doesn't check out"
		}
		return "Its signature is broken (" + e + "). Nobody vouches for this file."
	}
	return "None. Nobody vouches for this file."
}

// folderWords names the usual places a program runs from.
func folderWords(image string) string {
	l := strings.ToLower(strings.ReplaceAll(image, "/", `\`))
	for _, f := range []struct{ part, words string }{
		{`\downloads\`, "your Downloads folder"},
		{`\desktop\`, "your Desktop"},
		{`\documents\`, "your Documents folder"},
		{`\appdata\local\temp\`, "your Temp folder"},
		{`\windows\temp\`, "the Windows Temp folder"},
		{`\appdata\roaming\`, "your AppData folder"},
		{`\appdata\local\`, "your AppData folder"},
		{`\program files`, "Program Files"},
		{`\windows\`, "Windows"},
	} {
		if strings.Contains(l, f.part) {
			return f.words
		}
	}
	return ""
}

// base is a path's file name, whichever separator it uses (an alert from
// Windows is read on any system in the tests).
func base(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func dir(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return ""
}

func report(a *alerts.Alert, st *config.State) *Report {
	ap := a.Autopsy
	out := &Report{Pending: ap.Finished.IsZero(), Started: ap.Started, Finished: tp(ap.Finished), Answer: ap.Answer,
		Tone: autopsy.Tone(ap), Headline: ap.Headline, Summary: nonNil(ap.Summary), Steps: nonNil(ap.Steps),
		StepsUrgent: ap.Answer == alerts.AnswerRead, Unsure: nonNil(ap.Unsure), Leads: nonNil(ap.Leads),
		DataLeft: ap.Sent, DataLeftWhy: nonNil(ap.SentWhy), BaitAt: tp(ap.BaitAt), ProcessStart: tp(ap.ProcessStart),
		Timeline: []TimelineEvent{}, Reads: []Read{}, Sends: []Send{}, Addresses: []Address{}, Staged: []Staged{},
		Unpacked: []Unpacked{}, Watched: []Watched{}, OpenFiles: []OpenFile{}, Left: nonNil(ap.Left),
		AttackerWallet: ap.AttackerWallet, WalletNote: ap.WalletNote, Notes: nonNil(ap.Notes), Sections: []Section{},
		Evidence: Evidence{Saved: ap.Evidence != "", Folder: ap.Evidence, MemoryImage: ap.MemoryImage, MemoryScanned: ap.MemoryScanned}}
	baitAt := ap.BaitAt
	if baitAt.IsZero() {
		baitAt = a.Time
	}
	off := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Sub(baitAt).Milliseconds()
	}
	// When it was frozen: the freeze action's time, else the alert's
	// (which is when ABA acted).
	for _, d := range a.Actions {
		if d.OK && (d.Action == config.ActionFreeze || d.Action == config.ActionBlockProgram || d.Action == config.ActionKill) {
			t := d.Time
			out.FrozenAt = &t
			break
		}
	}
	if out.FrozenAt == nil && (a.Did(config.ActionFreeze) || st.IsFrozen(a.ID)) {
		t := a.Time
		out.FrozenAt = &t
	}

	for _, r := range ap.Reads {
		out.Reads = append(out.Reads, Read{Store: r.Store, Name: r.Name, Kind: r.Kind, Path: r.Path, At: r.At,
			OffsetMS: off(r.At), Count: r.Count, PID: r.PID, Image: r.Image, How: r.How})
	}
	for _, sd := range ap.Sends {
		out.Sends = append(out.Sends, Send{To: sd.To, Host: sd.Name, Bytes: sd.Bytes, BytesAfter: sd.BytesAfter, After: sd.After,
			First: sd.First, Last: sd.Last, OffsetMS: off(sd.First), Conns: sd.Conns, LAN: sd.LAN, UDP: sd.UDP,
			PID: sd.PID, Image: sd.Image, Via: sd.Via})
	}
	for _, ad := range ap.Addresses {
		out.Addresses = append(out.Addresses, Address{Kind: ad.Kind, Label: addressLabel(ad.Kind), Value: ad.Value,
			Where: ad.Where, Shareable: autopsy.Shareable(ad.Kind, ad.Value, ad.Where)})
	}
	for _, sg := range ap.Staged {
		x := Staged{Path: sg.Path, Name: base(sg.Path), Folder: dir(sg.Path), Size: sg.Size, Appeared: sg.Appeared,
			HeldOpen: sg.HeldOpen, What: sg.What, Archive: sg.Archive, Entries: []StagedEntry{}, More: sg.More, Saved: sg.Saved != ""}
		for _, e := range sg.Entries {
			t := entryTag(e.What)
			switch t {
			case "bait":
				x.Baits++
			case "real-copy":
				x.Real++
			}
			x.Entries = append(x.Entries, StagedEntry{Name: e.Name, Size: e.Size, Tag: t, What: e.What})
		}
		out.Staged = append(out.Staged, x)
	}
	for _, u := range ap.Unpacked {
		out.Unpacked = append(out.Unpacked, Unpacked{Dir: u.Dir, Files: u.Files, Size: u.Size})
	}
	seen := map[string]bool{}
	for _, w := range ap.Watched {
		x := Watched{Name: w.Name, State: "not-seen", Why: w.Why, Since: tp(w.Since)}
		switch {
		case w.Watched:
			x.State, x.Why = "watched", ""
		case w.Absent:
			x.State, x.Why = "absent", ""
		}
		if k := x.Name + "|" + x.State + "|" + x.Why; seen[k] {
			continue // two stores with one name (the Credential Manager's two folders)
		} else {
			seen[k] = true
		}
		out.Watched = append(out.Watched, x)
	}
	for _, f := range ap.OpenFiles {
		out.OpenFiles = append(out.OpenFiles, OpenFile{Path: f.Path, PID: f.PID, What: f.What})
	}
	out.Timeline = timeline(a, out, baitAt, off)
	for _, sec := range autopsy.Render(a) {
		out.Sections = append(out.Sections, Section{Key: sec.Key, Title: sec.Title, Lines: nonNil(sec.Lines)})
	}
	return out
}

// timeline is "the seconds that mattered": it started, read your real
// data, sent, opened the bait, was frozen.
func timeline(a *alerts.Alert, r *Report, baitAt time.Time, off func(time.Time) int64) []TimelineEvent {
	ev := []TimelineEvent{}
	add := func(e TimelineEvent) {
		e.OffsetMS = off(e.At)
		ev = append(ev, e)
	}
	if r.ProcessStart != nil {
		add(TimelineEvent{At: *r.ProcessStart, Kind: "start", Label: "It started", Detail: exeName(a)})
	}
	// One event per real store it read (the first read of each).
	firstRead := map[string]int{}
	for _, rd := range r.Reads {
		k := rd.Store + "|" + rd.Name
		if i, ok := firstRead[k]; ok {
			if rd.At.Before(r.Reads[i].At) {
				firstRead[k] = len(r.Reads)
			}
			continue
		}
		firstRead[k] = len(ev)
		add(TimelineEvent{At: rd.At, Kind: "read", Label: readLabel(rd), Detail: base(rd.Path), Bad: true})
	}
	for _, sd := range r.Sends {
		host := sd.Host
		if host == "" {
			host = sd.To
		}
		if host == "" {
			host = "other addresses"
		}
		add(TimelineEvent{At: sd.First, Kind: "send", Label: "Sent " + amount(sd.Bytes) + " to " + host, Detail: sd.To, Bad: sd.After})
	}
	what := "the bait"
	if len(a.Baits) > 0 {
		what = "the " + baitInfo(a.Baits[0].ID, a.Baits[0].Name).Label + " bait"
	}
	add(TimelineEvent{At: baitAt, Kind: "bait", Label: "Opened " + what})
	if r.FrozenAt != nil {
		label := "Frozen"
		if !a.Did(config.ActionFreeze) {
			label = "Cut off"
			if a.Did(config.ActionKill) {
				label = "Killed"
			}
		}
		add(TimelineEvent{At: *r.FrozenAt, Kind: "frozen", Label: label})
	}
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].At.Before(ev[j].At) })
	return ev
}

func amount(n int64) string {
	switch {
	case n <= 0:
		return "something"
	case n < 1024:
		return fmt.Sprintf("%d bytes", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

func addressLabel(kind string) string {
	switch kind {
	case autopsy.KindTelegram:
		return "Telegram bot"
	case autopsy.KindDiscord:
		return "Discord webhook"
	case autopsy.KindURL:
		return "Web address"
	case "connection":
		return "Connection"
	}
	return kind
}

// entryTag sorts an archive entry by what the autopsy said it is (see
// autopsy's classify: "a bait (…)", "…: the same bytes as your real file …",
// "named like …").
func entryTag(what string) string {
	switch {
	case strings.HasPrefix(what, "a bait"):
		return "bait"
	case strings.Contains(what, "the same bytes as your real file"):
		return "real-copy"
	case strings.HasPrefix(what, "named like"):
		return "named-like"
	}
	return ""
}

// ---- Baits ----

// Baits builds the Baits screen.
func (s *Source) Baits() *Baits {
	st := s.state()
	sum := s.baitsSummary()
	out := &Baits{Schema: Schema, Total: sum.Total, Healthy: sum.Healthy, LastCheck: sum.LastCheck, Items: []Bait{},
		Checks: healthItems(st.Health), ServiceRunning: s.ServiceRunning, Absent: []string{AbsentReplant, AbsentHeartbeatTrace}}
	touches := map[string][]Touch{}
	for _, a := range s.Alerts {
		seen := map[string]bool{}
		for _, b := range a.Baits {
			if seen[b.ID] {
				continue
			}
			seen[b.ID] = true
			touches[b.ID] = append(touches[b.ID], Touch{AlertID: a.ID, Program: exeName(a), Time: b.Time, Outcome: s.outcome(a), Access: b.Access})
		}
	}
	for _, id := range s.baitIDs() {
		bs := st.Baits[id]
		info := baitInfo(id, bs.Name)
		b := Bait{ID: id, Label: info.Label, Icon: info.Icon, Name: bs.Name, Description: info.Blurb, Category: info.Category,
			Kind: bs.Kind, Health: health(bs.Status), HealthNote: bs.StatusNote, Custom: strings.HasPrefix(id, "custom-"),
			CreatedAt: tp(bs.CreatedAt), LastCheck: tp(bs.LastCheck), Files: []BaitFile{}, TouchedBy: nonNil(touches[id])}
		for _, f := range bs.Files {
			b.Files = append(b.Files, BaitFile{Path: f.Path, Tripwire: f.Audit, Size: f.Size})
			b.HasText = b.HasText || f.Text != ""
		}
		out.Items = append(out.Items, b)
	}
	return out
}

// ---- Settings ----

// Settings builds the Settings screen.
func (s *Source) Settings() *Settings {
	cfg := s.cfg()
	out := &Settings{Schema: Schema, Preset: presetView(cfg).ID, Presets: []PresetOption{}, Instant: cfg.InstantFreeze,
		Recorder: !cfg.NoRecorder, Clipboard: Switchable{On: cfg.ClipboardBait, Supported: s.ClipboardSupported},
		Miners: Switchable{On: cfg.MinerTrap, Supported: s.MinersSupported}, Phone: Phone{On: s.PhoneVia != "", Via: s.PhoneVia},
		Update: s.updateView(), Learning: cfg.Learning(s.Now), Absent: []string{}}
	for _, id := range []string{"alert", "balanced", "strict"} {
		out.Presets = append(out.Presets, presetWords[id])
	}
	return out
}

// ---- Locked ----

// LockedView builds the locked view from the public status alone.
func LockedView(p *config.Public, version, alertID string, now time.Time) *Locked {
	out := &Locked{Schema: Schema, Mode: "locked", Version: version, Health: []HealthItem{}, Alert: alertID}
	if p == nil {
		out.State, out.Headline = "stopped", "Not running"
		return out
	}
	if p.Version != "" {
		out.Version = p.Version
	}
	out.Baits, out.BaitsHealthy, out.OpenAlerts = p.Baits, p.BaitsHealthy, p.OpenAlerts
	out.Heartbeat = tp(p.Heartbeat)
	out.Health = healthItems(p.Health)
	out.Isolated = p.IsolatedSince != nil
	out.SomethingFrozen = p.Frozen > 0 || p.Blocked > 0
	bad := p.Baits == 0 || p.BaitsHealthy < p.Baits
	for _, h := range p.Health {
		bad = bad || !h.OK
	}
	switch {
	case p.Heartbeat.IsZero() || now.Sub(p.Heartbeat) > staleAfter:
		out.State, out.Headline = "stopped", "Not running"
	case out.Isolated:
		out.State, out.Headline = "isolated", "Offline: something was caught"
	case out.SomethingFrozen:
		out.State, out.Headline = "frozen", "Something is frozen"
	case bad:
		out.State, out.Headline = "attention", "Needs a look"
	default:
		out.State, out.Headline = "protected", "Protected"
	}
	return out
}

// OneClickTrust reports whether "It's mine" trusts the program for good
// (else it lets it run once and trusts nothing; see trust.Rule).
func OneClickTrust(a *alerts.Alert) bool {
	_, why := trust.Rule(a)
	return why == ""
}

// exeName is the caught program's file name (an alert from Windows read on
// any system in the tests: both separators count).
func exeName(a *alerts.Alert) string {
	if a.Process != nil && a.Process.Image != "" {
		return base(a.Process.Image)
	}
	return a.ExeName()
}

// readLabel is a read in the timeline's words: "Read your real Chrome cookies".
func readLabel(rd Read) string {
	who := strings.TrimPrefix(rd.Name, "your ")
	what := "data"
	switch strings.ToLower(base(rd.Path)) {
	case "cookies":
		what = "cookies"
	case "login data", "logins.json", "key4.db":
		what = "saved passwords"
	case "local state":
		what = "key to its passwords"
	default:
		if rd.Kind == "wallet" {
			what = "wallet"
		}
	}
	return "Read your real " + who + " " + what
}
