// Package appapi is what the desktop app's page is shown: one view model per
// screen (Home, Caught + Full report, History, Baits, Settings, and the
// locked view for a person without administrator rights), built from ABA's
// own files (config, state, alerts and their autopsies), and the actions the
// page may ask for (Act), which run the installed CLI.
//
// It's plain Go with no Windows in it except how a child process is started,
// so it's tested on every system against the fixtures in testdata/, which
// are also the contract with the page (see CONTRACT.md).
//
// Everything that's a string here may come from a caught program (its file
// name, its command line, the webhook it sends to, the names in its zip): the
// page shows it as text, never as HTML.
package appapi

import "time"

// Schema is the version of the shapes below. It changes when a field is
// removed or changes meaning (adding a field doesn't change it).
const Schema = 1

// Things the Phase 1 app leaves out: a model lists the ones its screen would
// show in Absent, so the page hides them instead of showing zeros.
const (
	AbsentTouchChart      = "touchChart"      // Home: bait touches over the last 30 days
	AbsentChecklistTicks  = "checklistTicks"  // Full report: which of "Do these now" were done
	AbsentWebhookShutdown = "webhookShutdown" // Full report: "Shut down this webhook"
	AbsentReplant         = "replant"         // Baits: "Replant"
	AbsentBlockedSends    = "blockedSends"    // Full report: "3 sends blocked", "194 KB never left"
	AbsentProgramSize     = "programSize"     // Full report: the program's size (not recorded)
	AbsentHeartbeatTrace  = "heartbeatTrace"  // Baits: the bait's health over time (the heartbeat line)
)

// ---- Home ----

// Snapshot is the Home screen, and what every screen's frame shows (the
// title bar's state, the version in the corner).
type Snapshot struct {
	Schema     int          `json:"schema"`
	Mode       string       `json:"mode"` // always "full" (the locked view is Locked)
	Version    string       `json:"version"`
	Now        time.Time    `json:"now"`
	Protection Protection   `json:"protection"`
	Baits      BaitsSummary `json:"baits"`
	// QuietDays is how many whole days since the last catch (or since ABA
	// was installed, when nothing was ever caught). -1 when unknown.
	QuietDays int        `json:"quietDays"`
	LastCatch *time.Time `json:"lastCatch,omitempty"`
	Preset    PresetView `json:"preset"`
	Traps     Traps      `json:"traps"`
	Update    UpdateView `json:"update"`
	// Waiting are the alerts waiting for an answer, newest first: what's
	// frozen (or was cut off) and needs "Kill it", "Unfreeze once" or "It's
	// mine". The first one is what the Caught screen shows when the app
	// opens without --alert.
	Waiting []AlertRow `json:"waiting"`
	// Frozen is what ABA holds frozen right now.
	Frozen []FrozenItem `json:"frozen"`
	// RecentQuiet are the latest harmless touches ABA only noted (signed
	// programs like Windows Search), newest first, at most 10.
	RecentQuiet []AlertRow `json:"recentQuiet"`
	Absent      []string   `json:"absent"`
}

// Protection is the one-word state at the top of Home and in the title bar.
type Protection struct {
	// State is one of:
	//   "protected" - running, baits in place, nothing waiting
	//   "frozen"    - something is frozen (or cut off) and waits for an answer
	//   "isolated"  - the whole PC is cut off from the network (Strict)
	//   "attention" - running, but something's wrong (a bait missing, a check failing)
	//   "stopped"   - the service isn't running (or hasn't checked in for 5 minutes)
	State string `json:"state"`
	// Headline is the state in a few words ("Protected", "Something is frozen").
	Headline string `json:"headline"`
	// Problems are what's wrong, in words, when State is "attention" or "stopped".
	Problems       []string     `json:"problems"`
	ServiceRunning bool         `json:"serviceRunning"`
	Heartbeat      *time.Time   `json:"heartbeat,omitempty"` // the service's last check-in
	Health         []HealthItem `json:"health"`              // the service's own checks
	IsolatedSince  *time.Time   `json:"isolatedSince,omitempty"`
	// Learning: ABA is in learning mode until LearningUntil (only alerts
	// below critical are held back).
	Learning      bool       `json:"learning"`
	LearningUntil *time.Time `json:"learningUntil,omitempty"`
}

// HealthItem is one of the service's checks ("Instant freeze armed").
type HealthItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// BaitsSummary is the bait count on Home and the bait tags in its scene.
type BaitsSummary struct {
	Total     int         `json:"total"`   // planted (not retired)
	Healthy   int         `json:"healthy"` // of those, in place and armed
	LastCheck *time.Time  `json:"lastCheck,omitempty"`
	ByKind    []KindCount `json:"byKind"` // by category, in the catalog's order
	Tags      []BaitTag   `json:"tags"`   // one per planted bait, most tempting first
}

// KindCount is how many baits of one category there are.
type KindCount struct {
	Category string `json:"category"` // Files, Browsers, Wallets, Apps, Credentials, Custom
	Total    int    `json:"total"`
	Healthy  int    `json:"healthy"`
}

// BaitTag is a bait as a label in the scene.
type BaitTag struct {
	ID     string `json:"id"`
	Label  string `json:"label"`  // short: "Discord login"
	Icon   string `json:"icon"`   // see CONTRACT.md for the set
	Health string `json:"health"` // ok | missing | error
}

// PresetView is the protection level.
type PresetView struct {
	ID   string `json:"id"`   // alert | balanced | strict | custom
	Name string `json:"name"` // "Balanced"
	Says string `json:"says"` // "On a catch: freeze it, cut its internet"
}

// Traps are the traps' cards on Home.
type Traps struct {
	Baits     int        `json:"baits"`
	Instant   bool       `json:"instant"`
	Recorder  bool       `json:"recorder"`
	Clipboard Switchable `json:"clipboard"`
	Miners    Switchable `json:"miners"`
}

// Switchable is a trap that may not exist on this system.
type Switchable struct {
	On        bool `json:"on"`
	Supported bool `json:"supported"`
}

// UpdateView is the version and what the updater last did.
type UpdateView struct {
	Version    string     `json:"version"`
	Latest     string     `json:"latest,omitempty"` // newest release seen
	Available  bool       `json:"available"`        // Latest is newer than Version
	Auto       bool       `json:"auto"`             // updates install themselves
	Updatable  bool       `json:"updatable"`        // a release build (a dev build never updates)
	LastCheck  *time.Time `json:"lastCheck,omitempty"`
	LastResult string     `json:"lastResult,omitempty"`
	UpdatedAt  *time.Time `json:"updatedAt,omitempty"`
}

// FrozenItem is one program ABA holds frozen.
type FrozenItem struct {
	AlertID string    `json:"alertId"`
	Program string    `json:"program"` // file name
	PID     uint32    `json:"pid"`
	Since   time.Time `json:"since"`
}

// ---- History ----

// History is every alert, newest first.
type History struct {
	Schema int           `json:"schema"`
	Counts HistoryCounts `json:"counts"`
	Items  []AlertRow    `json:"items"`
	Absent []string      `json:"absent"`
}

// HistoryCounts are the History screen's three tiles and more.
type HistoryCounts struct {
	Total   int `json:"total"`
	Caught  int `json:"caught"` // frozen, cut off or killed by ABA (Outcome frozen/killed/resumed/stopped/cut-off)
	Frozen  int `json:"frozen"` // frozen right now
	Killed  int `json:"killed"`
	Trusted int `json:"trusted"` // you said "It's mine"
	Quiet   int `json:"quiet"`   // harmless touches, noted quietly
	Tests   int `json:"tests"`
}

// AlertRow is an alert in a list.
type AlertRow struct {
	ID       string    `json:"id"`
	ShortID  string    `json:"shortId"` // what `aba kill` takes
	Time     time.Time `json:"time"`
	Category string    `json:"category"` // see Category*
	Tier     string    `json:"tier"`     // info | warn | critical
	Outcome  string    `json:"outcome"`  // see Outcome*
	Program  string    `json:"program"`  // file name, "" for alerts about ABA itself
	Title    string    `json:"title"`
	// Line is one short sentence for the row ("Opened the Discord bait.").
	Line string `json:"line"`
	Bait string `json:"bait,omitempty"` // the first bait's label
	Icon string `json:"icon"`           // stealer | miner | clipper | trusted | quiet | test | system
	Test bool   `json:"test"`
}

// What an alert was about.
const (
	CategoryStealer = "stealer" // a program opened, changed or deleted a bait
	CategoryMiner   = "miner"   // logged in at the miner trap's fake pool
	CategoryClipper = "clipper" // swapped the bait wallet address on the clipboard
	CategoryTamper  = "tamper"  // tried to switch part of ABA off
	CategoryBait    = "bait"    // a bait went missing, lost its tripwire, was retired
	CategoryTest    = "test"    // `aba test`
)

// How an alert ended (or stands).
const (
	OutcomeFrozen   = "frozen"   // frozen now, waiting for an answer
	OutcomeCutOff   = "cut-off"  // its internet is cut (not frozen), waiting for an answer
	OutcomeKilled   = "killed"   // ended by you ("Kill it")
	OutcomeTrusted  = "trusted"  // you said it's yours
	OutcomeResumed  = "resumed"  // let run again once by you, nothing trusted
	OutcomeStopped  = "stopped"  // was frozen, has ended since (or was released)
	OutcomeAlerted  = "alerted"  // told you, did nothing (Alert only, or not critical)
	OutcomeNoted    = "noted"    // harmless touch, noted quietly
	OutcomeAnswered = "answered" // answered some other way (see the alert's note)
)

// ---- Caught + Full report ----

// Alert is the Caught screen and the Full report of one alert.
type Alert struct {
	Schema   int       `json:"schema"`
	ID       string    `json:"id"`
	ShortID  string    `json:"shortId"`
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Tier     string    `json:"tier"`
	Outcome  string    `json:"outcome"`
	Status   string    `json:"status"` // open | resolved | noted
	Note     string    `json:"note,omitempty"`
	Title    string    `json:"title"`
	Summary  string    `json:"summary,omitempty"`
	Test     bool      `json:"test"`
	Learning bool      `json:"learning"`

	// FrozenNow: ABA holds it frozen right now; FrozenSince since when.
	FrozenNow   bool       `json:"frozenNow"`
	FrozenSince *time.Time `json:"frozenSince,omitempty"`
	// CutOff: its internet is cut right now (a block for its file).
	CutOff bool `json:"cutOff"`
	// Isolated: the whole PC was cut off for this alert and still is.
	Isolated bool `json:"isolated"`
	// Instant: caught the moment it opened the bait (instant freeze).
	Instant bool `json:"instant"`
	// LatencyMS is how long after the bait was opened ABA stopped it
	// (0: unknown, or nothing was stopped).
	LatencyMS int64 `json:"latencyMs"`

	Program *Program  `json:"program,omitempty"` // nil for an alert about ABA itself
	Baits   []BaitHit `json:"baits"`
	Reasons []string  `json:"reasons"` // why ABA rated it as it did

	// Did is what ABA did, in words ("Froze it", "Cut its internet").
	Did []Done `json:"did"`
	// Buttons are the answers this alert takes, in order (see Button*).
	// Empty when it's answered or there's nothing to answer.
	Buttons []string `json:"buttons"`
	// Checklist is what to do after a catch, in words (no tick state).
	Checklist []string `json:"checklist"`

	// Mine is what a caught miner asked the fake pool for.
	Mine *Mine `json:"mine,omitempty"`
	// Clipper is the wallet a caught clipper swapped in.
	Clipper *Clipper `json:"clipper,omitempty"`

	// Report is the full report: nil when ABA didn't (or couldn't) look into
	// the program (an alert about ABA itself, an old alert, Alert only).
	Report *Report  `json:"report,omitempty"`
	Absent []string `json:"absent"`
}

// The answers a Caught screen offers.
const (
	ButtonKill    = "kill"    // "Kill it": end it, keep the evidence (it stays cut off)
	ButtonResume  = "resume"  // "Unfreeze once": let it run again, trust nothing
	ButtonTrust   = "trust"   // "It's mine": undo everything, stop alerting about it
	ButtonRelease = "release" // "Reconnect this PC" (it was isolated)
)

// Program is the caught program.
type Program struct {
	Name string `json:"name"` // file name
	Path string `json:"path"`
	PID  uint32 `json:"pid"`
	// Signed: someone vouches for it (the system checked the signature).
	Signed bool   `json:"signed"`
	Signer string `json:"signer,omitempty"`
	// Signature is the signature in words ("None. Nobody vouches for this file.").
	Signature string `json:"signature"`
	SHA256    string `json:"sha256,omitempty"`
	// Folder is where it ran from, in words ("your Downloads folder"); ""
	// when it's not one of the usual places.
	Folder      string `json:"folder,omitempty"`
	StartedBy   string `json:"startedBy,omitempty"` // file name of what started it, or "a program that has ended since"
	CommandLine string `json:"commandLine,omitempty"`
	User        string `json:"user,omitempty"`
	Exited      bool   `json:"exited"` // it had already ended when ABA looked
	// Origin is where it was downloaded from, as the browser marked the file
	// (the program could have written that mark itself: a lead, not proof).
	Origin *Origin `json:"origin,omitempty"`
}

// Origin is a file's download mark.
type Origin struct {
	URL      string `json:"url,omitempty"`
	Referrer string `json:"referrer,omitempty"`
	Via      string `json:"via,omitempty"`
	Line     string `json:"line"` // in words
}

// BaitHit is a bait the alert is about.
type BaitHit struct {
	ID     string    `json:"id"`
	Label  string    `json:"label"`
	Icon   string    `json:"icon"`
	Name   string    `json:"name"` // the bait's long name ("Discord token store")
	Path   string    `json:"path"`
	Access string    `json:"access"` // read | delete | write | swap | mine
	Time   time.Time `json:"time"`
}

// Done is one thing ABA did.
type Done struct {
	Action string    `json:"action"` // freeze | block-program | kill | isolate | disable-adapters | left-running
	OK     bool      `json:"ok"`
	Words  string    `json:"words"` // "Froze it", or "Couldn't kill it: …"
	Time   time.Time `json:"time"`
}

// Mine is a caught miner's login.
type Mine struct {
	Pool   string `json:"pool,omitempty"`
	Wallet string `json:"wallet,omitempty"`
	Agent  string `json:"agent,omitempty"`
}

// Clipper is what a caught clipper swapped in.
type Clipper struct {
	Wallet string `json:"wallet"`
	Note   string `json:"note"`
}

// Report is the full report (from the autopsy).
type Report struct {
	// Pending: ABA is still looking (the autopsy started, not finished).
	Pending  bool       `json:"pending"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`

	// Answer to "did it take my real data?": read | no-sign | cannot-tell.
	Answer string `json:"answer"`
	// Tone: bad (it read real data and may have sent it), warn (read but
	// nothing left, or can't tell), good (no sign it read anything of yours).
	Tone     string   `json:"tone"`
	Headline string   `json:"headline"`
	Summary  []string `json:"summary"`
	// Steps are what to do now (the "Do these now" list), in words.
	Steps []string `json:"steps"`
	// StepsUrgent: Steps are "Do this now, from another device" (it read
	// your data), else "To be safe".
	StepsUrgent bool     `json:"stepsUrgent"`
	Unsure      []string `json:"unsure"` // why ABA can't be sure
	Leads       []string `json:"leads"`  // things that point to a theft without proving it

	// DataLeft answers "did anything leave this PC before the freeze?":
	// "sent" | "nothing" | "cannot-tell" | "" (not looked at).
	DataLeft    string   `json:"dataLeft"`
	DataLeftWhy []string `json:"dataLeftWhy"` // why ABA can't tell, when it can't

	// BaitAt is when it opened the bait: the timeline's zero.
	BaitAt       *time.Time `json:"baitAt,omitempty"`
	ProcessStart *time.Time `json:"processStart,omitempty"`
	FrozenAt     *time.Time `json:"frozenAt,omitempty"`
	// Timeline is "the seconds that mattered", in time order.
	Timeline []TimelineEvent `json:"timeline"`

	Reads     []Read     `json:"reads"`
	Sends     []Send     `json:"sends"`
	Addresses []Address  `json:"addresses"`
	Staged    []Staged   `json:"staged"`
	Unpacked  []Unpacked `json:"unpacked"`
	Watched   []Watched  `json:"watched"`
	OpenFiles []OpenFile `json:"openFiles"`
	Left      []string   `json:"left"` // what will start it again, in words

	AttackerWallet string `json:"attackerWallet,omitempty"`
	WalletNote     string `json:"walletNote,omitempty"`

	Evidence Evidence `json:"evidence"`
	Notes    []string `json:"notes"` // what couldn't be looked at

	// Sections are the whole report as text, section by section (what
	// `aba autopsy` prints): for "Copy", and for anything above the page
	// doesn't lay out.
	Sections []Section `json:"sections"`
}

// TimelineEvent is one moment of the timeline.
type TimelineEvent struct {
	At time.Time `json:"at"`
	// OffsetMS is At minus the moment it opened the bait (negative: before).
	OffsetMS int64  `json:"offsetMs"`
	Kind     string `json:"kind"` // start | read | send | bait | frozen
	Label    string `json:"label"`
	Detail   string `json:"detail,omitempty"`
	// Bad: this is the part that hurts (it read real data; data got out).
	Bad bool `json:"bad"`
}

// Read is a real store's file it opened, for certain.
type Read struct {
	Store    string    `json:"store"`
	Name     string    `json:"name"` // "your Chrome"
	Kind     string    `json:"kind"`
	Path     string    `json:"path"`
	At       time.Time `json:"at"`
	OffsetMS int64     `json:"offsetMs"`
	Count    int       `json:"count"`
	PID      uint32    `json:"pid"`
	Image    string    `json:"image,omitempty"`
	How      string    `json:"how"` // how ABA knows
}

// Send is what one of its processes sent to one address.
type Send struct {
	To         string    `json:"to"`             // address:port ("" for more than ABA keeps apart)
	Host       string    `json:"host,omitempty"` // the name it looked up, when known
	Bytes      int64     `json:"bytes"`
	BytesAfter int64     `json:"bytesAfter"`
	After      bool      `json:"after"` // some of it after it opened your data
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	OffsetMS   int64     `json:"offsetMs"` // First minus the bait time
	Conns      int       `json:"conns"`
	LAN        bool      `json:"lan"`
	UDP        bool      `json:"udp"`
	PID        uint32    `json:"pid"`
	Image      string    `json:"image,omitempty"`
	Via        string    `json:"via,omitempty"` // "started by pid 812"
}

// Address is somewhere it may have been sending to.
type Address struct {
	Kind  string `json:"kind"`  // telegram-bot | discord-webhook | url | connection
	Label string `json:"label"` // "Discord webhook"
	Value string `json:"value"`
	Where string `json:"where"` // memory | file | memory+file | connection
	// Shareable: it's safe to share (not just a string from its memory that
	// may be your own data it collected).
	Shareable bool `json:"shareable"`
}

// Staged is a file that appeared while it ran.
type Staged struct {
	Path     string        `json:"path"`
	Name     string        `json:"name"` // file name, hidden characters shown as ‹U+200B›
	Folder   string        `json:"folder"`
	Size     int64         `json:"size"`
	Appeared time.Time     `json:"appeared"`
	HeldOpen bool          `json:"heldOpen"` // it has it open: certainly its
	What     string        `json:"what,omitempty"`
	Archive  string        `json:"archive,omitempty"`
	Entries  []StagedEntry `json:"entries"`
	More     int           `json:"more"`
	Saved    bool          `json:"saved"` // a copy is in the evidence folder
	Baits    int           `json:"baits"` // entries that are baits
	Real     int           `json:"real"`  // entries that are copies of your real files
}

// StagedEntry is one file inside a staged archive.
type StagedEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// Tag: "bait" (a bait: fake, nothing lost), "real-copy" (the same bytes
	// as one of your real files), "named-like" (named like a bait or a real
	// file, contents don't match), "" (nothing ABA knows).
	Tag  string `json:"tag"`
	What string `json:"what,omitempty"`
}

// Unpacked is a folder of its own code that appeared while it ran.
type Unpacked struct {
	Dir   string `json:"dir"`
	Files int    `json:"files"`
	Size  int64  `json:"size"`
}

// Watched is how well one real store was watched while it ran.
type Watched struct {
	Name  string     `json:"name"`
	State string     `json:"state"` // watched | absent | not-seen
	Why   string     `json:"why,omitempty"`
	Since *time.Time `json:"since,omitempty"`
}

// OpenFile is a file it has open.
type OpenFile struct {
	Path string `json:"path"`
	PID  uint32 `json:"pid"`
	What string `json:"what,omitempty"`
}

// Evidence is what was kept.
type Evidence struct {
	Saved         bool   `json:"saved"`
	Folder        string `json:"folder,omitempty"` // admin-only
	MemoryImage   bool   `json:"memoryImage"`
	MemoryScanned int64  `json:"memoryScanned"` // bytes of its memory looked through
}

// Section is one section of the report as text.
type Section struct {
	Key   string   `json:"key"`
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

// ---- Baits ----

// Baits is the Baits screen.
type Baits struct {
	Schema         int          `json:"schema"`
	Total          int          `json:"total"`
	Healthy        int          `json:"healthy"`
	LastCheck      *time.Time   `json:"lastCheck,omitempty"`
	Items          []Bait       `json:"items"`
	Checks         []HealthItem `json:"checks"` // the service's checks, for "Instant freeze armed…"
	ServiceRunning bool         `json:"serviceRunning"`
	Absent         []string     `json:"absent"`
}

// Bait is one planted bait.
type Bait struct {
	ID          string     `json:"id"`
	Label       string     `json:"label"` // "Discord login"
	Icon        string     `json:"icon"`
	Name        string     `json:"name"`        // the catalog's name
	Description string     `json:"description"` // the catalog's description ("Fake token, next to the real one")
	Category    string     `json:"category"`
	Kind        string     `json:"kind"`   // file | decoy | canary
	Health      string     `json:"health"` // ok | missing | error
	HealthNote  string     `json:"healthNote,omitempty"`
	Custom      bool       `json:"custom"` // you made it a bait
	CreatedAt   *time.Time `json:"createdAt,omitempty"`
	LastCheck   *time.Time `json:"lastCheck,omitempty"`
	Files       []BaitFile `json:"files"`
	// HasText: "See what's inside" has something to show (Act "bait-show").
	HasText bool `json:"hasText"`
	// TouchedBy are the alerts about this bait, newest first.
	TouchedBy []Touch `json:"touchedBy"`
}

// BaitFile is one file of a bait.
type BaitFile struct {
	Path     string `json:"path"`
	Tripwire bool   `json:"tripwire"` // watched (the others are there to make it look real)
	Size     int64  `json:"size"`
}

// Touch is an alert about a bait.
type Touch struct {
	AlertID string    `json:"alertId"`
	Program string    `json:"program"`
	Time    time.Time `json:"time"`
	Outcome string    `json:"outcome"`
	Access  string    `json:"access"`
}

// ---- Settings ----

// Settings is the Settings screen.
type Settings struct {
	Schema    int            `json:"schema"`
	Preset    string         `json:"preset"` // alert | balanced | strict | custom
	Presets   []PresetOption `json:"presets"`
	Instant   bool           `json:"instant"`
	Recorder  bool           `json:"recorder"`
	Clipboard Switchable     `json:"clipboard"`
	Miners    Switchable     `json:"miners"`
	Phone     Phone          `json:"phone"`
	Update    UpdateView     `json:"update"`
	Learning  bool           `json:"learning"`
	Absent    []string       `json:"absent"`
}

// PresetOption is one stop of the protection level slider.
type PresetOption struct {
	ID   string `json:"id"`
	Name string `json:"name"` // "Alert only"
	Says string `json:"says"` // "Tells you. Stops nothing."
	// Does are what it does on a catch, as icons: alert | freeze | cut | offline.
	Does []string `json:"does"`
}

// Phone is phone alerts (no address, token or topic: those stay in the
// secrets file).
type Phone struct {
	On  bool   `json:"on"`
	Via string `json:"via,omitempty"` // ntfy | telegram | discord | pushover | …
}

// ---- Locked ----

// Locked is all a person without administrator rights is shown: what
// config.Public allows (no paths, bait or program names, alert contents, or
// how ABA responds).
type Locked struct {
	Schema  int    `json:"schema"`
	Mode    string `json:"mode"` // always "locked"
	Version string `json:"version"`
	// State: protected | frozen | isolated | attention | stopped (see Protection).
	State    string `json:"state"`
	Headline string `json:"headline"`
	// SomethingFrozen: something is frozen or cut off and an administrator
	// needs to decide.
	SomethingFrozen bool         `json:"somethingFrozen"`
	Isolated        bool         `json:"isolated"`
	Baits           int          `json:"baits"`
	BaitsHealthy    int          `json:"baitsHealthy"`
	OpenAlerts      int          `json:"openAlerts"`
	Heartbeat       *time.Time   `json:"heartbeat,omitempty"`
	Health          []HealthItem `json:"health"`
	// Alert: the app was opened for an alert (its ID only; the alert itself
	// is for administrators).
	Alert string `json:"alert,omitempty"`
}

// ---- Actions ----

// Result is what an action did.
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Details are the action's own (see CONTRACT.md): the bait's contents
	// for bait-show, the version for update-check, the alert for test.
	Details any `json:"details,omitempty"`
}

// Event is a progress line of a long action (test, update).
type Event struct {
	Event string    `json:"event"` // step | done
	Text  string    `json:"text"`
	Time  time.Time `json:"time"`
}
