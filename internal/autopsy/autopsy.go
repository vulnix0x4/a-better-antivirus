// Package autopsy looks into a caught program while it's frozen, to answer
// the question a catch leaves you with: did it already take my real
// passwords, cookies or keys before it hit the bait?
//
// It runs after the freeze and after the first notification, never before:
// it can take seconds, and the freeze and the alert can't wait. What it
// gathers:
//
//   - From the flight recorder (package recorder): which real stores this
//     program, or anything it started, opened, and when, relative to the
//     bait; and how well each store was watched while it ran.
//   - The files it has open, and the files that appeared where stealers put
//     what they collect while it ran; for an archive, the names inside it
//     and which of them are baits and which are real.
//   - Where it was sending: its connections still open, and the generic
//     shapes of an exfiltration address (a Telegram bot, a Discord webhook, a
//     web address) in its memory and its program file.
//
// Then one of three honest answers (see decide.go), and an evidence folder
// only administrators can read, saved before `aba kill` can erase anything.
package autopsy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/recorder"
)

// Case is what the autopsy is about: copied out of the alert when it's
// raised, so the autopsy never touches an alert the engine is still adding to.
type Case struct {
	AlertID string
	Test    bool
	PID     uint32
	Image   string
	Tree    []uint32 // the caught process and what it started, as forensics found them
	Frozen  []uint32 // everything frozen for this alert
	BaitAt  time.Time
	Wallet  string // the attacker's wallet address, when a clipper swapped one in
	Conns   []procinfo.Conn
	User    config.UserInfo
	// BaitFiles are the bait files (path -> the bait's name), and Stores the
	// real stores: what's found is checked against both.
	BaitFiles map[string]string
	Stores    []baits.Store
}

// Hooks are the operating system's part, and the service's.
type Hooks struct {
	// Recorder asks the flight recorder; why says why it can't ("" if it can).
	Recorder    func(q recorder.Query) (res recorder.Result, why string)
	StartedAt   func(pid uint32) (time.Time, error)
	OpenFiles   func(pid uint32) ([]string, error)
	ReadMemory  func(pid uint32, limit int64, fn func(base uint64, b []byte) bool) (int64, error)
	WorkingDir  func(pid uint32) string
	StagingDirs func(c *Case) []Dir
	// EvidenceDir is where evidence folders go ("" to save none), and
	// MemoryImage whether one includes a copy of the program's memory.
	EvidenceDir string
	MemoryImage bool
	// Settle is how long to wait for the operating system's reports of the
	// last moments before the freeze to come in.
	Settle time.Duration
	Logf   func(format string, a ...any)
}

// Dir is a folder to look through for staged files, and how deep.
type Dir struct {
	Path  string
	Depth int
}

// Limits on how much is read.
const (
	memPerProcess = 1 << 30
	memTotal      = 2 << 30
	memImageMax   = 512 << 20
	fileScanMax   = 64 << 20
	sampleMax     = 200 << 20
	stagedCopyMax = 100 << 20
)

func (h Hooks) logf(f string, a ...any) {
	if h.Logf != nil {
		h.Logf(f, a...)
	}
}

// Run looks into c and returns what it found. It never fails as a whole:
// what it couldn't do is in Notes.
func Run(c Case, h Hooks) *alerts.Autopsy {
	a := &alerts.Autopsy{Started: time.Now(), AttackerWallet: c.Wallet}
	if h.Settle > 0 {
		time.Sleep(h.Settle)
	}
	to := time.Now()

	// Who it is: the processes, and when the first of them started.
	var members []recorder.Member
	seen := map[uint32]bool{}
	var start time.Time
	startWhy := ""
	for _, p := range append(append([]uint32{c.PID}, c.Frozen...), c.Tree...) {
		if p == 0 || seen[p] {
			continue
		}
		seen[p] = true
		m := recorder.Member{PID: p}
		if h.StartedAt != nil {
			if t, err := h.StartedAt(p); err == nil {
				m.Start = t
				if start.IsZero() || t.Before(start) {
					start = t
				}
			} else if p == c.PID {
				startWhy = "it had exited by the time ABA looked"
			}
		}
		members = append(members, m)
	}
	if startWhy != "" {
		start = time.Time{} // the caught program itself is gone: no window can be trusted
	}

	f := facts{start: start, startWhy: startWhy, baitAt: c.BaitAt}
	if h.Recorder != nil {
		from := start
		if from.IsZero() {
			from = c.BaitAt.Add(-10 * time.Minute)
		}
		res, why := h.Recorder(recorder.Query{Members: members, From: from, To: to})
		f.res, f.recorderOn, f.recorderWhy = res, why == "", why
		if why != "" {
			// Without the recorder, coverage is still listed (all unwatched).
			f.res.Stores = res.Stores
		}
	} else {
		f.recorderWhy = "the service wasn't there to ask"
		for _, s := range c.Stores {
			n := len(s.Resolve())
			f.res.Stores = append(f.res.Stores, recorder.Coverage{Store: s.ID, Name: s.Name, Kind: s.Kind, Files: n, Absent: n == 0, Why: "not watched"})
		}
	}

	realFiles := map[string]string{}
	for _, s := range c.Stores {
		for _, p := range s.Resolve() {
			if _, bait := c.BaitFiles[p]; !bait {
				realFiles[p] = s.Name
			}
		}
	}
	k := newKnown(c.BaitFiles, c.Stores, realFiles)

	// Files it has open.
	open := map[string]bool{}
	if h.OpenFiles != nil {
		for _, m := range members {
			files, err := h.OpenFiles(m.PID)
			if err != nil {
				if m.PID == c.PID {
					a.Notes = append(a.Notes, "Couldn't list the files it has open: "+err.Error())
				}
				continue
			}
			for _, p := range files {
				if open[p] || systemFile(p) {
					continue
				}
				open[p] = true
				fs := alerts.FileSeen{Path: p, PID: m.PID}
				if name, ok := c.BaitFiles[p]; ok {
					fs.What = "a bait (" + name + ")"
				} else if s, ok := baits.StoreFor(c.Stores, p); ok {
					fs.What = "a file of " + s.Name
					f.held = append(f.held, alerts.StoreRead{Store: s.ID, Name: s.Name, Kind: s.Kind, Path: p, At: to, PID: m.PID, How: "it has it open right now"})
				}
				if len(a.OpenFiles) < 300 {
					a.OpenFiles = append(a.OpenFiles, fs)
				}
			}
		}
	}

	// What appeared where stealers stage what they collect.
	since := start
	if since.IsZero() {
		since = c.BaitAt.Add(-10 * time.Minute)
		a.Notes = append(a.Notes, "Not knowing when it started, ABA looked for files that appeared in the 10 minutes before the catch.")
	}
	var dirs []Dir
	if h.StagingDirs != nil {
		dirs = h.StagingDirs(&c)
	}
	if h.WorkingDir != nil {
		if wd := h.WorkingDir(c.PID); wd != "" {
			dirs = append(dirs, Dir{Path: wd, Depth: 2})
		}
	}
	if c.Image != "" {
		dirs = append(dirs, Dir{Path: filepath.Dir(c.Image), Depth: 2})
	}
	for p := range open {
		dirs = append(dirs, Dir{Path: filepath.Dir(p), Depth: 0})
	}
	skip := map[string]bool{}
	for p := range c.BaitFiles {
		skip[p] = true
	}
	skip[c.Image] = true // the program itself
	staged, where := findStaged(dirs, since.Add(-time.Second), skip, h.EvidenceDir)
	a.StagedWhere = where
	for _, st := range staged {
		st.HeldOpen = open[st.Path]
		if kind := archiveKind(st.Path); kind != "" {
			st.Archive = kind
			if kind == "7z" || kind == "rar" {
				st.What = "a " + kind + " archive (ABA can't list what's in one)"
			} else {
				entries, more, err := k.listArchive(st.Path, kind)
				st.Entries, st.More = entries, more
				if err != nil {
					st.What = "an archive ABA couldn't read all of: " + err.Error()
				}
				nb, nr := 0, 0
				for _, e := range entries {
					switch {
					case strings.HasPrefix(e.What, "a bait"):
						nb++
					case strings.Contains(e.What, "the same bytes as your real file"):
						nr++
						stName, stID, stKind := storeOfWhat(c.Stores, e.What)
						f.stagedReal = append(f.stagedReal, stagedFact{path: st.Path + " > " + e.Name, store: stID, name: stName, kind: stKind, what: "the archive " + st.Path, held: st.HeldOpen, at: st.Appeared})
					case strings.HasPrefix(e.What, "named like your") || strings.HasPrefix(e.What, "named like a file of"):
						f.leads = append(f.leads, fmt.Sprintf("The archive %s, which appeared at %s while it ran, holds %s, %s.", st.Path, clock(st.Appeared), e.Name, e.What))
					}
				}
				if st.What == "" {
					st.What = fmt.Sprintf("an archive of %d files (%d baits, %d copies of your real files)", len(entries)+more, nb, nr)
				}
			}
		} else {
			size := st.Size
			p := st.Path
			v, what := k.classify(p, size, func() (uint32, bool) { return fileCRC(p) })
			st.What = what
			if v == isReal {
				stName, stID, stKind := storeOfWhat(c.Stores, what)
				f.stagedReal = append(f.stagedReal, stagedFact{path: p, store: stID, name: stName, kind: stKind, what: "the file " + p, held: st.HeldOpen, at: st.Appeared})
			}
		}
		a.Staged = append(a.Staged, *st)
	}

	// Where it was sending: its memory, its file, its connections.
	mem := NewScanner()
	var image *memImage
	if h.EvidenceDir != "" && h.MemoryImage && !c.Test {
		image = newMemImage(evidenceDir(h.EvidenceDir, c.AlertID), c.PID)
	}
	if h.ReadMemory != nil {
		var total int64
		for _, m := range members {
			if total >= memTotal {
				break
			}
			var last uint64
			n, err := h.ReadMemory(m.PID, memPerProcess, func(base uint64, b []byte) bool {
				if base != last {
					mem.Break()
				}
				last = base + uint64(len(b))
				mem.Feed(b)
				if image != nil && m.PID == c.PID {
					image.write(base, b)
				}
				return true
			})
			total += n
			if err != nil && m.PID == c.PID {
				a.Notes = append(a.Notes, "Couldn't read its memory: "+err.Error())
			}
		}
		a.MemoryScanned = total
	}
	inFile := map[string]string{}
	if c.Image != "" {
		fs := NewScanner()
		if err := scanFile(c.Image, fs); err == nil {
			inFile = fs.Found()
		}
	}
	a.Addresses = Addresses(mem.Found(), inFile)
	for _, cn := range c.Conns {
		if cn.Remote != "" && !strings.HasPrefix(cn.Remote, "127.") && !strings.HasPrefix(cn.Remote, "[::1]") && cn.Remote != "*:*" {
			a.Addresses = append(a.Addresses, alerts.Address{Kind: KindConn, Value: cn.Remote, Where: "connection"})
		}
	}
	a.Notes = append(a.Notes, "Connections: only the ones still open when it was frozen are known; any it had already closed aren't.")

	decide(f, a)

	if h.EvidenceDir != "" {
		if err := saveEvidence(c, h, a, image, staged); err != nil {
			a.Notes = append(a.Notes, "Couldn't save all the evidence: "+err.Error())
		}
	}
	a.Finished = time.Now()
	if a.Evidence != "" {
		writeJSON(filepath.Join(a.Evidence, "autopsy.json"), a)
	}
	h.logf("autopsy of %s: %s (%s)", c.AlertID, a.Answer, a.Headline)
	return a
}

// storeOfWhat finds the store a classification names ("your real Chrome: the
// same bytes…" starts with the store's name).
func storeOfWhat(stores []baits.Store, what string) (name, id, kind string) {
	for _, s := range stores {
		if strings.HasPrefix(what, s.Name+":") {
			return s.Name, s.ID, s.Kind
		}
	}
	return "one of your stores", "", ""
}

// systemFile: the operating system's own files every program has open.
func systemFile(p string) bool {
	l := strings.ToLower(filepath.ToSlash(p))
	for _, pre := range []string{"c:/windows/", "/system/", "/usr/lib/", "/usr/share/", "/lib/", "/lib64/", "/usr/lib64/", "/dev/", "/proc/", "/sys/",
		"/private/var/db/", "/library/preferences/", "/usr/libexec/"} {
		if strings.HasPrefix(l, pre) {
			return true
		}
	}
	return false
}

// scanFile looks through (at most fileScanMax of) a file for addresses.
func scanFile(p string, s *Scanner) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	var n int64
	for n < fileScanMax {
		k, err := f.Read(buf)
		if k > 0 {
			s.Feed(buf[:k])
			n += int64(k)
		}
		if err != nil {
			break
		}
	}
	return nil
}

func evidenceDir(root, alertID string) string { return filepath.Join(root, alertID) }

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// sortStaged puts what the program holds open first, then newest first.
func sortStaged(s []*alerts.Staged) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].HeldOpen != s[j].HeldOpen {
			return s[i].HeldOpen
		}
		return s[i].Appeared.After(s[j].Appeared)
	})
}
