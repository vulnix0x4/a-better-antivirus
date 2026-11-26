// Package alerts defines detections and stores them as JSON files in the data dir.
package alerts

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/classify"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/origin"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// Kinds of alert.
const (
	KindRead          = "read"           // a bait was read
	KindDelete        = "delete"         // a bait was deleted or renamed
	KindWrite         = "write"          // a bait was opened to be changed (overwritten), not read
	KindBaitMissing   = "bait-missing"   // a bait vanished without a delete event
	KindAuditRemoved  = "audit-removed"  // a bait's audit rule was stripped
	KindAuditDisabled = "audit-disabled" // file auditing was switched off system-wide
	KindDecoyRetired  = "decoy-retired"  // the real app got installed; decoy removed
	KindTamper        = "tamper"         // something tried to switch part of ABA off
	KindTest          = "test"
	KindClipper       = "clipper" // a program swapped the wallet address ABA put on the clipboard
	KindMiner         = "miner"   // a program logged in to mine at the miner trap's fake pool
)

// StatusNoted is the status of an alert ABA noted quietly: a read by a program
// that looks legitimate, about which nothing was done. It's in the history,
// but no popup or phone alert went out and nothing waits for an answer.
// ("open" waits for one; "resolved" got one.)
const StatusNoted = "noted"

// Mine is a caught miner's login: what the popup and phone alert show.
type Mine struct {
	Pool   string `json:"pool,omitempty"`
	Wallet string `json:"wallet,omitempty"`
	Agent  string `json:"agent,omitempty"`
}

// Lines are the miner's details, one fact per line.
func (m *Mine) Lines() []string {
	if m == nil {
		return nil
	}
	var out []string
	if m.Wallet != "" {
		out = append(out, "Wallet it mines for: "+m.Wallet)
	}
	if m.Agent != "" {
		out = append(out, "Miner: "+m.Agent)
	}
	return out
}

type BaitHit struct {
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Path   string    `json:"path"`
	Access string    `json:"access"` // read | delete | write | swap | mine
	Time   time.Time `json:"time"`
}

type Process struct {
	PID         uint32            `json:"pid"`
	Image       string            `json:"image"`
	CommandLine string            `json:"commandLine,omitempty"`
	Dir         string            `json:"dir,omitempty"` // the folder it ran in, where the system shows that
	User        string            `json:"user,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	Signature   provenance.Result `json:"signature"`
	Parents     []procinfo.Parent `json:"parents,omitempty"`
	Connections []procinfo.Conn   `json:"connections,omitempty"`
	TreePIDs    []uint32          `json:"treePids,omitempty"`
	Exited      bool              `json:"exited,omitempty"`
	// Origin is where it was downloaded from, as the browser marked the file
	// (or the script it ran, or what started it). The program could have
	// written that mark itself: it's a lead, not proof.
	Origin *origin.Origin `json:"origin,omitempty"`
}

type ActionResult struct {
	Action config.Action `json:"action"`
	OK     bool          `json:"ok"`
	Detail string        `json:"detail,omitempty"`
	Time   time.Time     `json:"time"`
}

type Alert struct {
	ID         string           `json:"id"`
	Time       time.Time        `json:"time"`
	Kind       string           `json:"kind"`
	Tier       config.Tier      `json:"tier"`
	Title      string           `json:"title"`
	Summary    string           `json:"summary,omitempty"`
	Learning   bool             `json:"learning,omitempty"`
	Test       bool             `json:"test,omitempty"`
	Baits      []BaitHit        `json:"baits,omitempty"`
	Process    *Process         `json:"process,omitempty"`
	Verdict    classify.Verdict `json:"verdict"`
	Actions    []ActionResult   `json:"actions,omitempty"`
	LatencyMS  int64            `json:"latencyMs,omitempty"`  // event logged -> first response
	DeliveryMS int64            `json:"deliveryMs,omitempty"` // event logged -> ABA received it
	Instant    bool             `json:"instant,omitempty"`    // caught the moment it opened the bait (instant freeze), not via the event log
	Status     string           `json:"status"`               // open | resolved
	Note       string           `json:"note,omitempty"`
	// Autopsy is what ABA found out about the caught program while it was
	// frozen: what real things it had opened, what it staged, where it was
	// sending. Filled in a moment after the alert went out (see package autopsy).
	Autopsy *Autopsy `json:"autopsy,omitempty"`
	// Mine is what a program caught by the miner trap asked for.
	Mine *Mine `json:"mine,omitempty"`
}

// The three answers an autopsy gives to "did it take my real data?".
const (
	AnswerRead    = "read"        // it opened real things: here they are, act now
	AnswerNoSign  = "no-sign"     // no sign it did, over everything ABA was watching
	AnswerUnknown = "cannot-tell" // ABA can't tell, and says why
)

// The three answers to "did anything leave this PC before it was frozen?",
// from ABA's network record.
const (
	SentNothing = "nothing"     // the record proves nothing it ran sent anything once it had your data
	SentSome    = "sent"        // it (or something it started) connected out after opening your data
	SentUnknown = "cannot-tell" // ABA can't tell, and says why
)

// Autopsy is what ABA found out about a caught program while it was frozen.
// Everything in it is something ABA saw; where it couldn't see, it says so.
type Autopsy struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`

	Answer   string   `json:"answer"`
	Headline string   `json:"headline"`
	Summary  []string `json:"summary,omitempty"` // a few lines that explain the answer
	Steps    []string `json:"steps,omitempty"`   // what to do about what it read (or may have)
	Unsure   []string `json:"unsure,omitempty"`  // why ABA can't tell, when it can't
	Leads    []string `json:"leads,omitempty"`   // things that point to a theft without proving it
	// Sent answers whether anything left this PC before the freeze (one of
	// the Sent* constants; "" when it wasn't looked at), SentWhy why ABA
	// can't tell when it can't, and Sends what the network record saw it
	// send.
	Sent    string    `json:"sent,omitempty"`
	SentWhy []string  `json:"sentWhy,omitempty"`
	Sends   []NetSend `json:"sends,omitempty"`

	ProcessStart time.Time    `json:"processStart,omitempty"` // when the first of its processes started
	BaitAt       time.Time    `json:"baitAt,omitempty"`
	Reads        []StoreRead  `json:"reads,omitempty"`
	Watched      []StoreWatch `json:"watched,omitempty"`
	OpenFiles    []FileSeen   `json:"openFiles,omitempty"`
	Staged       []Staged     `json:"staged,omitempty"`
	StagedWhere  []string     `json:"stagedWhere,omitempty"` // the folders looked through for staged files
	// Unpacked are folders of the program's own code that appeared while it
	// ran (a self-unpacking program's libraries): counted, not listed.
	Unpacked []Unpacked `json:"unpacked,omitempty"`
	// Left is what it left behind that will start it again (a copy of itself
	// in a startup folder…), in words.
	Left      []string  `json:"left,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`

	MemoryScanned  int64    `json:"memoryScanned,omitempty"` // bytes of its memory looked through
	AttackerWallet string   `json:"attackerWallet,omitempty"`
	WalletNote     string   `json:"walletNote,omitempty"`  // what the wallet is ("" means a clipper's swapped-in one)
	Evidence       string   `json:"evidence,omitempty"`    // the folder the evidence was saved to
	MemoryImage    bool     `json:"memoryImage,omitempty"` // the evidence includes a copy of its memory
	Notes          []string `json:"notes,omitempty"`       // what couldn't be looked at, and why
}

// StoreRead is a real store's file the program opened, for certain.
type StoreRead struct {
	Store string    `json:"store"`
	Name  string    `json:"name"` // "your Chrome"
	Kind  string    `json:"kind"`
	Path  string    `json:"path"`
	At    time.Time `json:"at"`
	Count int       `json:"count,omitempty"`
	PID   uint32    `json:"pid,omitempty"`
	Image string    `json:"image,omitempty"`
	How   string    `json:"how"` // how ABA knows: "the flight recorder saw it open it", "it has it open"
}

// NetSend is what one of the program's processes sent to one address.
type NetSend struct {
	PID   uint32    `json:"pid"`
	Image string    `json:"image,omitempty"`
	Via   string    `json:"via,omitempty"` // "started by pid 812": a program it started
	To    string    `json:"to"`            // address:port; "" for more addresses than ABA keeps apart
	Name  string    `json:"name,omitempty"`
	LAN   bool      `json:"lan,omitempty"` // on the local network
	UDP   bool      `json:"udp,omitempty"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Bytes int64     `json:"bytes"`
	Conns int       `json:"conns,omitempty"`
	// After: some of it was sent after it opened your data (or, when ABA
	// doesn't know when that was, while it ran), roughly BytesAfter bytes.
	After      bool  `json:"after"`
	BytesAfter int64 `json:"bytesAfter,omitempty"`
}

// StoreWatch is how well one real store was watched while the program ran.
type StoreWatch struct {
	Store   string    `json:"store"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind,omitempty"`
	Watched bool      `json:"watched"`
	Absent  bool      `json:"absent,omitempty"`
	Since   time.Time `json:"since,omitempty"`
	Why     string    `json:"why,omitempty"`
}

// FileSeen is a file the program has open.
type FileSeen struct {
	Path string `json:"path"`
	PID  uint32 `json:"pid"`
	What string `json:"what,omitempty"` // "a bait", "your real Chrome's file"
}

// Staged is a file that appeared while the program ran, where stealers put
// what they collect.
type Staged struct {
	Path     string         `json:"path"`
	Size     int64          `json:"size"`
	Appeared time.Time      `json:"appeared"`
	HeldOpen bool           `json:"heldOpen,omitempty"` // the program has it open: certainly its
	What     string         `json:"what,omitempty"`
	Archive  string         `json:"archive,omitempty"` // zip, tar…
	Entries  []ArchiveEntry `json:"entries,omitempty"`
	More     int            `json:"more,omitempty"`  // entries not listed
	Saved    string         `json:"saved,omitempty"` // its copy in the evidence folder
}

// Unpacked is a folder of a program's own code that appeared while it ran.
type Unpacked struct {
	Dir   string `json:"dir"`
	Files int    `json:"files"`
	Size  int64  `json:"size"`
}

// ArchiveEntry is one file inside a staged archive.
type ArchiveEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	What string `json:"what,omitempty"`
}

// Address is somewhere the program may have been sending to.
type Address struct {
	Kind  string `json:"kind"` // telegram-bot, discord-webhook, url, connection
	Value string `json:"value"`
	Where string `json:"where"` // memory, file, memory+file, connection
}

// NewID returns a sortable, unique alert ID.
func NewID(t time.Time) string {
	b := make([]byte, 2)
	rand.Read(b)
	return t.Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func (a *Alert) Did(act config.Action) bool {
	for _, r := range a.Actions {
		if r.Action == act && r.OK {
			return true
		}
	}
	return false
}

func (a *Alert) AddAction(act config.Action, err error, detail string) {
	r := ActionResult{Action: act, OK: err == nil, Detail: detail, Time: time.Now()}
	if err != nil {
		r.Detail = strings.TrimSpace(detail + " " + err.Error())
	}
	a.Actions = append(a.Actions, r)
}

// ExeName is the reader's file name, or a placeholder. An alert without a
// process is one ABA raises itself (a decoy retired, a bait put back).
func (a *Alert) ExeName() string {
	if a.Process == nil {
		return "ABA"
	}
	if a.Process.Image == "" {
		if a.Process != nil && a.Process.PID == 4 {
			return "System (kernel / network share)"
		}
		return "unknown process"
	}
	return procinfo.BaseName(a.Process.Image)
}

// BrowserName is what people call the browser whose executable is image
// ("Chrome" for chrome.exe), or else the executable's name. image may be a
// Windows path on any system (an alert shown elsewhere, a test), so both
// separators count: no browser's file name has either.
func BrowserName(image string) string {
	base := image
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	switch strings.TrimSuffix(strings.ToLower(base), ".exe") {
	case "chrome", "google-chrome", "google chrome":
		return "Chrome"
	case "msedge", "microsoft-edge", "microsoft edge":
		return "Edge"
	case "brave", "brave-browser", "brave browser":
		return "Brave"
	case "firefox", "firefox-bin", "firefox-esr":
		return "Firefox"
	}
	return base
}

func file(id string) string { return filepath.Join(paths.AlertsDir(), id+".json") }

// SaveFromService is how the service saves an alert, every time, including
// again later (an autopsy finished, more of what the program did): it keeps
// what was written to the alert's file meanwhile by you, through the CLI
// (`aba resume`, `kill`, `release`, `trust`, a popup's answer). See Merge.
func SaveFromService(a *Alert) error {
	if b, err := os.ReadFile(file(a.ID)); err == nil {
		var disk Alert
		if json.Unmarshal(b, &disk) == nil {
			return Save(Merge(&disk, a))
		}
	}
	return Save(a)
}

// Merge is the service's copy of an alert (svc) saved over the one on disk:
// the service's copy, plus what the CLI wrote to the file meanwhile. The
// service adds to an alert (what it found, did and saw), the CLI resolves it.
// So:
//   - a resolution on disk (status "resolved" and its note) stays;
//   - the actions are both lists together (the CLI adds "killed by you");
//   - the bait hits are both lists together;
//   - an autopsy only on disk stays, and the evidence folder the CLI saved
//     (see respond.Preserve) is kept in the service's autopsy;
//
// and everything else is the service's.
func Merge(disk, svc *Alert) *Alert {
	if disk == nil {
		return svc
	}
	out := *svc
	if disk.Status == "resolved" && out.Status != "resolved" {
		out.Status, out.Note = disk.Status, disk.Note
	}
	out.Actions = append([]ActionResult(nil), svc.Actions...)
	for _, d := range disk.Actions {
		seen := false
		for _, s := range svc.Actions {
			seen = seen || (s.Action == d.Action && s.OK == d.OK && s.Detail == d.Detail && s.Time.Equal(d.Time))
		}
		if !seen {
			out.Actions = append(out.Actions, d)
		}
	}
	out.Baits = append([]BaitHit(nil), svc.Baits...)
	for _, d := range disk.Baits {
		seen := false
		for _, s := range svc.Baits {
			seen = seen || (strings.EqualFold(s.Path, d.Path) && s.Access == d.Access)
		}
		if !seen {
			out.Baits = append(out.Baits, d)
		}
	}
	switch {
	case out.Autopsy == nil:
		out.Autopsy = disk.Autopsy
	case disk.Autopsy != nil && out.Autopsy.Evidence == "" && disk.Autopsy.Evidence != "":
		ap := *out.Autopsy
		ap.Evidence, ap.MemoryImage = disk.Autopsy.Evidence, disk.Autopsy.MemoryImage
		out.Autopsy = &ap
	}
	return &out
}

// Save writes the alert (admin only).
func Save(a *Alert) error {
	if err := os.MkdirAll(paths.AlertsDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	tmp := file(a.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file(a.ID))
}

// Load reads an alert by full ID or unique prefix/suffix.
func Load(id string) (*Alert, error) {
	b, err := os.ReadFile(file(id))
	if errors.Is(err, os.ErrNotExist) {
		all, _ := ids()
		var matches []string
		for _, x := range all {
			if strings.HasPrefix(x, id) || strings.HasSuffix(x, id) {
				matches = append(matches, x)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("no alert %q", id)
		case 1:
			b, err = os.ReadFile(file(matches[0]))
		default:
			return nil, fmt.Errorf("%q matches %d alerts; be more specific", id, len(matches))
		}
	}
	if err != nil {
		return nil, err
	}
	a := &Alert{}
	return a, json.Unmarshal(b, a)
}

func ids() ([]string, error) {
	entries, err := os.ReadDir(paths.AlertsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".json") {
			out = append(out, strings.TrimSuffix(n, ".json"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// List returns up to limit alerts, newest first (limit <= 0: all).
func List(limit int) ([]*Alert, error) {
	all, err := ids()
	if err != nil {
		return nil, err
	}
	var out []*Alert
	for _, id := range all {
		if limit > 0 && len(out) >= limit {
			break
		}
		if a, err := Load(id); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// Counts returns how many alerts there are, and how many of the latest 100
// are still open.
func Counts() (total, open int) {
	all, _ := ids()
	total = len(all)
	for i, id := range all {
		if i >= 100 {
			break
		}
		if a, err := Load(id); err == nil && a.Status == "open" {
			open++
		}
	}
	return total, open
}

// Update loads, modifies and saves an alert.
func Update(id string, fn func(*Alert)) (*Alert, error) {
	a, err := Load(id)
	if err != nil {
		return nil, err
	}
	fn(a)
	return a, Save(a)
}

// Checklist is what to do after a critical detection.
func Checklist(a *Alert) []string {
	var steps []string
	if a.Kind == KindMiner {
		// A miner costs you electricity and speed, not data; but what
		// brought it often brought a stealer too, and it comes back by
		// itself if what starts it stays.
		steps = []string{
			"If you didn't start a miner yourself: kill it (Yes in the alert, or `aba kill` with the alert's number).",
			"Miners come back by themselves. Look in Task Scheduler and in Settings > Apps > Startup for anything you don't recognise, and in the alert for where the program came from.",
			"What brings a miner (a cracked game, a cheat, a \"free\" tool) often brings a stealer too. From another device, change your important passwords, email first.",
			"You can report the wallet in the alert to the mining pool it wanted: pools block wallets that malware mines for.",
			platform.CleanupStep,
		}
	} else if a.Kind == KindClipper {
		// A clipper changes what you paste; it doesn't need to read files.
		// What it costs you is a payment sent to the wrong wallet.
		steps = []string{
			"Don't send crypto from this " + platform.PC + " until it's cleaned. Anywhere you must paste an address, compare every character with the real one on another device.",
			"From another device, check your recent crypto transfers. One sent to an address you don't recognise went to the attacker: contact the exchange's or wallet's support right away.",
			"Clippers often come with a stealer. From another device (your phone), change your passwords, email first, and move crypto to a NEW wallet created on a clean device.",
			platform.CleanupStep,
		}
	} else {
		steps = []string{
			"Keep this " + platform.PC + " offline. Don't log in to anything from it until it's cleaned.",
			"From another device (your phone), change your passwords: email first (it resets everything else), then banking, then anything saved in this " + platform.PC + "'s browsers.",
			"Log out everywhere: stolen browser cookies keep sessions alive after a password change. Use 'Sign out of all devices' for Google, Microsoft, Discord, Steam, Telegram (Settings > Devices > Terminate all), social media.",
			"Crypto: move funds to a NEW wallet created on a clean device. Treat every seed phrase this " + platform.PC + " has ever seen as burned.",
			"Turn on 2FA with an authenticator app (not SMS) for important accounts.",
			platform.CleanupStep,
		}
	}
	if a.Process != nil && a.Process.SHA256 != "" {
		steps = append(steps, "Look the file up on VirusTotal from another device: https://www.virustotal.com/gui/file/"+a.Process.SHA256)
	}
	return steps
}
