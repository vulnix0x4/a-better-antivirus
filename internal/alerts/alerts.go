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
	KindBaitMissing   = "bait-missing"   // a bait vanished without a delete event
	KindAuditRemoved  = "audit-removed"  // a bait's audit rule was stripped
	KindAuditDisabled = "audit-disabled" // file auditing was switched off system-wide
	KindDecoyRetired  = "decoy-retired"  // the real app got installed; decoy removed
	KindTamper        = "tamper"         // something tried to switch part of ABA off
	KindTest          = "test"
	KindClipper       = "clipper" // a program swapped the wallet address ABA put on the clipboard
)

type BaitHit struct {
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Path   string    `json:"path"`
	Access string    `json:"access"` // read | delete | swap
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
}

// The three answers an autopsy gives to "did it take my real data?".
const (
	AnswerRead    = "read"        // it opened real things: here they are, act now
	AnswerNoSign  = "no-sign"     // no sign it did, over everything ABA was watching
	AnswerUnknown = "cannot-tell" // ABA can't tell, and says why
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

	ProcessStart time.Time    `json:"processStart,omitempty"` // when the first of its processes started
	BaitAt       time.Time    `json:"baitAt,omitempty"`
	Reads        []StoreRead  `json:"reads,omitempty"`
	Watched      []StoreWatch `json:"watched,omitempty"`
	OpenFiles    []FileSeen   `json:"openFiles,omitempty"`
	Staged       []Staged     `json:"staged,omitempty"`
	StagedWhere  []string     `json:"stagedWhere,omitempty"` // the folders looked through for staged files
	Addresses    []Address    `json:"addresses,omitempty"`

	MemoryScanned  int64    `json:"memoryScanned,omitempty"` // bytes of its memory looked through
	AttackerWallet string   `json:"attackerWallet,omitempty"`
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

// ExeName is the reader's file name, or a placeholder.
func (a *Alert) ExeName() string {
	if a.Process == nil || a.Process.Image == "" {
		if a.Process != nil && a.Process.PID == 4 {
			return "System (kernel / network share)"
		}
		return "unknown process"
	}
	return procinfo.BaseName(a.Process.Image)
}

func file(id string) string { return filepath.Join(paths.AlertsDir(), id+".json") }

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
	if a.Kind == KindClipper {
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
