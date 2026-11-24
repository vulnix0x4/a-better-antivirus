// Package eswatch notices bait files being opened on macOS, through Apple's
// Endpoint Security: for now through eslogger, Apple's command-line client
// for it, which needs root and Full Disk Access but no entitlement from Apple.
//
// eslogger can't be told which files to watch: it reports every open on the
// Mac (on a busy one, thousands a second) as a line of JSON. So each line is
// first searched for the bait paths as plain bytes, and only the few that
// mention one are read as JSON. It reports after the fact: by the time ABA
// hears of an open, the program may have read the file (a few milliseconds
// earlier, typically). A native Endpoint Security client, once Apple grants
// ABA the entitlement, would be told only about the baits and could hold the
// opener inside its open, the way Linux and Windows do; it would replace
// eslogger behind the same Watcher.
//
// Besides the baits it follows two more things, because the program that
// opens a bait is often not the one behind it:
//
//   - Every program started (exec), with its parent, arguments and signature:
//     a short-lived reader (cat, a shell running one line) and what started
//     it are usually gone by the time the engine looks.
//   - Finder's log of who sends it Apple events (finder_darwin.go): a script
//     that tells Finder to copy a file has the file opened by Finder's helper,
//     not by itself.
package eswatch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Op is what was done to the bait.
type Op int

const (
	Read   Op = iota + 1 // opened for reading, or copied (clone, copyfile)
	Delete               // deleted, or renamed away
	Link                 // given a second name (a hard link)
	Write                // opened only to write: to overwrite it, not to read it
)

// Process is what the kernel said about a process in an event.
type Process struct {
	PID, PPID uint32
	UID       uint32
	Image     string
	Platform  bool   // Apple's own code
	TeamID    string // the developer's team, for Developer ID and App Store code
	SigningID string
	CSFlags   uint32
	TTY       string // its controlling terminal ("" for none)
	Started   time.Time
}

// CSValid is the kernel's "the signature is valid" flag (CS_VALID).
const CSValid = 0x1

// Event is one bait touched.
type Event struct {
	At   time.Time // when it happened, by the kernel's clock
	Got  time.Time // when the watcher heard of it
	Op   Op
	Kind string // eslogger's name for it: open, clone, copyfile, rename, link, unlink…
	// Path is the bait. Alias is the other name involved: where a hard link
	// or a renamed bait now is.
	Path  string
	Alias string
	Proc  Process
}

// Exec is one program started.
type Exec struct {
	Proc  Process
	Args  []string
	Cwd   string
	Stdin string // the terminal its input comes from, "" if a pipe or nothing
}

// Watcher follows eslogger. Set OnEvent (and OnExec, OnStoreOpen) before Run.
type Watcher struct {
	OnEvent func(Event)
	OnExec  func(Exec)
	// OnStoreOpen gets every read of a file under one of the store prefixes
	// (see SyncStores): the flight recorder's feed. It's never an alert.
	OnStoreOpen func(Event)
	Logf        func(format string, a ...any)

	mu      sync.Mutex
	files   []string
	aliases map[string][2]string // another name for a bait (a hard link), in lower case -> as written, the bait
	needles [][]byte
	baitM   *matcher
	stores  [][]byte // the real stores' path prefixes, as needles (see SyncStores)
	storeM  *matcher
	cmd     *exec.Cmd
	running bool
	since   time.Time
	lastErr error
	closed  bool
	wake    chan struct{}

	Lines, Bytes, Matched, StoreLines atomic.Uint64
}

func New() *Watcher { return &Watcher{wake: make(chan struct{}, 1)} }

// Events eslogger is asked for: everything that reads, copies or moves a
// file, and every program started.
var events = []string{"open", "clone", "copyfile", "rename", "link", "unlink", "exchangedata", "exec"}

// ErrNoAccess is returned (by Status) while macOS won't let eslogger run:
// the service lacks Full Disk Access.
var ErrNoAccess = errors.New("macOS won't let ABA watch files until File Access Monitor has Full Disk Access")

// Sync sets which files are baits.
func (w *Watcher) Sync(files []string) {
	w.mu.Lock()
	w.files = append([]string(nil), files...)
	w.rebuild()
	w.mu.Unlock()
}

// SyncStores sets the path prefixes of the real stores the flight recorder
// watches (baits.Store.Prefixes). A line that mentions one is read as JSON
// and every read in it handed to OnStoreOpen: which of them are really a
// store's files is for the recorder to say.
func (w *Watcher) SyncStores(prefixes []string) {
	n := needles(prefixes)
	w.mu.Lock()
	w.stores, w.storeM = n, newMatcher(n)
	w.mu.Unlock()
}

// AddAlias watches another name a bait was given (a hard link made to it), so
// that reading it by that name is reported as reading the bait.
func (w *Watcher) AddAlias(alias, bait string) {
	w.mu.Lock()
	if w.aliases == nil {
		w.aliases = map[string][2]string{}
	}
	w.aliases[strings.ToLower(alias)] = [2]string{alias, bait}
	w.rebuild()
	w.mu.Unlock()
}

// DropAlias stops watching a second name a bait was given.
func (w *Watcher) DropAlias(alias string) {
	w.mu.Lock()
	delete(w.aliases, strings.ToLower(alias))
	w.rebuild()
	w.mu.Unlock()
}

func (w *Watcher) rebuild() {
	all := append([]string(nil), w.files...)
	for _, a := range w.aliases {
		all = append(all, a[0])
	}
	w.needles = needlesFold(all)
	w.baitM = newMatcher(w.needles)
}

// bait says which bait path is, by its own name or another one.
func (w *Watcher) bait(path string) (bait, alias string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, f := range w.files {
		if strings.EqualFold(f, path) {
			return f, "", true
		}
	}
	if a, found := w.aliases[strings.ToLower(path)]; found {
		return a[1], path, true
	}
	return "", "", false
}

// Watching reports whether path is one of the baits.
func (w *Watcher) Watching(path string) bool {
	_, _, ok := w.bait(path)
	return ok
}

// Counts reports how many bait files are watched right now, and how many
// should be.
func (w *Watcher) Counts() (armed, want int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running && time.Since(w.since) > time.Second {
		return len(w.files), len(w.files)
	}
	return 0, len(w.files)
}

// Status says whether eslogger is running, and if not, why.
func (w *Watcher) Status() (running bool, since time.Time, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running, w.since, w.lastErr
}

// Close stops watching.
func (w *Watcher) Close() {
	w.mu.Lock()
	w.closed = true
	cmd := w.cmd
	w.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Retry makes Run try eslogger again now instead of at its next attempt
// (after Full Disk Access was switched on).
func (w *Watcher) Retry() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Watcher) logf(f string, a ...any) {
	if w.Logf != nil {
		w.Logf(f, a...)
	}
}

// Run keeps eslogger running until Close: it's started again whenever it
// stops (macOS may end it; Full Disk Access may be switched on only later).
func (w *Watcher) Run() {
	wait := time.Second
	for {
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if closed {
			return
		}
		started := time.Now()
		err := w.runOnce()
		w.mu.Lock()
		w.running, w.cmd = false, nil
		if w.closed {
			w.mu.Unlock()
			return
		}
		w.lastErr = err
		w.mu.Unlock()
		if time.Since(started) > time.Minute {
			wait = time.Second
		}
		if errors.Is(err, ErrNoAccess) {
			// Asking is what puts the program in Full Disk Access's list.
			touchPrivacyDatabase()
			wait = 3 * time.Second
		} else {
			w.logf("eslogger stopped: %v; starting it again in %s", err, wait)
		}
		select {
		case <-w.wake:
		case <-time.After(wait):
		}
		if wait < 30*time.Second && !errors.Is(err, ErrNoAccess) {
			wait *= 2
		}
	}
}

// touchPrivacyDatabase tries to read a file only programs with Full Disk
// Access may read. The attempt is what makes macOS list the program in
// System Settings > Privacy & Security > Full Disk Access, ready to be
// switched on.
func touchPrivacyDatabase() {
	if f, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db"); err == nil {
		f.Close()
	}
}

// HasFullDiskAccess reports whether this process may read what only
// programs with Full Disk Access may.
func HasFullDiskAccess() bool {
	f, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func (w *Watcher) runOnce() error {
	cmd := exec.Command("/usr/bin/eslogger", events...)
	// eslogger ignores every process in its own process group. In ours, that
	// would be whatever started this one too (a terminal, a test); in a group
	// of its own it ignores only itself.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	cmd.Stderr = &limited{w: &stderr, n: 4096}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start eslogger: %w", err)
	}
	w.mu.Lock()
	w.cmd, w.running, w.since, w.lastErr = cmd, true, time.Now(), nil
	w.mu.Unlock()
	w.read(out)
	werr := cmd.Wait()
	msg := strings.TrimSpace(stderr.String())
	if strings.Contains(msg, "NOT_PERMITTED") || strings.Contains(msg, "Not permitted") || strings.Contains(msg, "not permitted") {
		return ErrNoAccess
	}
	if msg != "" {
		return fmt.Errorf("%s (%v)", firstLine(msg), werr)
	}
	if werr == nil {
		werr = errors.New("eslogger exited")
	}
	return werr
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

var (
	execMarks = [][]byte{[]byte(`"event_type":9,`), []byte(`"event_type":9}`)}
	self      = uint32(os.Getpid())
)

func (w *Watcher) read(out io.Reader) {
	r := bufio.NewReaderSize(out, 4<<20)
	for {
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// One event bigger than the buffer (an exec with a huge
			// environment): skip the rest of it.
			for err == bufio.ErrBufferFull {
				_, err = r.ReadSlice('\n')
			}
			continue
		}
		if len(line) > 0 {
			w.Lines.Add(1)
			w.Bytes.Add(uint64(len(line)))
			w.line(line)
		}
		if err != nil {
			return
		}
	}
}

func (w *Watcher) line(line []byte) {
	got := time.Now()
	w.mu.Lock()
	bm, sm, ss := w.baitM, w.storeM, w.stores
	w.mu.Unlock()
	isExec := matchAny(line, execMarks)
	isBait := !isExec && bm.match(line)
	isStore := !isExec && w.OnStoreOpen != nil && sm.match(line)
	if !isExec && !isBait && !isStore {
		return
	}
	var e rawEvent
	if json.Unmarshal(line, &e) != nil {
		return
	}
	if isExec {
		if x, ok := e.exec(); ok && w.OnExec != nil {
			w.OnExec(x)
		}
		return
	}
	if e.Process.AuditToken.Pid == self {
		return // ABA's own service planting and checking baits
	}
	if isStore {
		w.StoreLines.Add(1)
		for _, ev := range e.touches(got, w.storeOf(ss), nil) {
			if ev.Op == Read {
				w.OnStoreOpen(ev)
			}
		}
	}
	if !isBait {
		return
	}
	for _, ev := range e.touches(got, w.bait, w.DropAlias) {
		w.Matched.Add(1)
		if w.OnEvent != nil {
			w.OnEvent(ev)
		}
	}
}

// ---- eslogger's JSON ----

type auditToken struct {
	Pid  uint32 `json:"pid"`
	EUID uint32 `json:"euid"`
}

type file struct {
	Path string `json:"path"`
}

type rawProcess struct {
	AuditToken auditToken `json:"audit_token"`
	PPid       uint32     `json:"ppid"`
	Executable file       `json:"executable"`
	SigningID  string     `json:"signing_id"`
	TeamID     *string    `json:"team_id"`
	CSFlags    uint32     `json:"codesigning_flags"`
	Platform   bool       `json:"is_platform_binary"`
	StartTime  string     `json:"start_time"`
	TTY        *file      `json:"tty"`
}

func (p *rawProcess) facts() Process {
	out := Process{PID: p.AuditToken.Pid, PPID: p.PPid, UID: p.AuditToken.EUID, Image: p.Executable.Path,
		Platform: p.Platform, SigningID: p.SigningID, CSFlags: p.CSFlags}
	if p.TeamID != nil {
		out.TeamID = *p.TeamID
	}
	if p.TTY != nil {
		out.TTY = p.TTY.Path
	}
	out.Started, _ = time.Parse(time.RFC3339Nano, p.StartTime)
	return out
}

type rawEvent struct {
	Time    string                     `json:"time"`
	Process rawProcess                 `json:"process"`
	Event   map[string]json.RawMessage `json:"event"`
}

func (e *rawEvent) exec() (Exec, bool) {
	raw, ok := e.Event["exec"]
	if !ok {
		return Exec{}, false
	}
	var x struct {
		Target rawProcess `json:"target"`
		Args   []string   `json:"args"`
		Cwd    *file      `json:"cwd"`
		FDs    []struct {
			FD     int `json:"fd"`
			FDType int `json:"fdtype"`
		} `json:"fds"`
	}
	if json.Unmarshal(raw, &x) != nil {
		return Exec{}, false
	}
	out := Exec{Proc: x.Target.facts(), Args: x.Args}
	if x.Cwd != nil {
		out.Cwd = x.Cwd.Path
	}
	// Its input: a file (fdtype 1) when it's a terminal; a pipe (6) or
	// socket (2) otherwise.
	for _, fd := range x.FDs {
		if fd.FD == 0 && fd.FDType == 1 {
			out.Stdin = out.Proc.TTY
		}
	}
	return out, true
}

// storeOf is touches' matcher for the real stores: a path under one of the
// prefixes (the recorder says which store, if any, it belongs to).
func (w *Watcher) storeOf(ss [][]byte) func(string) (string, string, bool) {
	return func(p string) (string, string, bool) {
		q, _ := json.Marshal(p)
		q = q[1 : len(q)-1]
		for _, n := range ss {
			if bytes.HasPrefix(q, n) {
				return p, "", true
			}
		}
		return "", "", false
	}
}

// touches lists the baits this event is about.
func (e *rawEvent) touches(got time.Time, baitOf func(string) (string, string, bool), dropAlias func(string)) []Event {
	at, err := time.Parse(time.RFC3339Nano, e.Time)
	if err != nil {
		at = got
	}
	base := Event{At: at, Got: got, Proc: e.Process.facts()}
	var out []Event
	add := func(op Op, path, alias string) {
		if path == "" {
			return
		}
		bait, via, ok := baitOf(path)
		if !ok {
			return
		}
		if via != "" && op == Delete && dropAlias != nil {
			// Removing (or renaming) the second name a bait was given leaves
			// the bait where it was: nothing to report, and nothing more to
			// watch under that name.
			dropAlias(via)
			return
		}
		if via != "" && op != Link {
			alias = via // read through a hard link it made earlier
		}
		ev := base
		ev.Op, ev.Path, ev.Alias = op, bait, alias
		out = append(out, ev)
	}
	for kind, raw := range e.Event {
		base.Kind = kind
		var x map[string]json.RawMessage
		if json.Unmarshal(raw, &x) != nil {
			continue
		}
		switch kind {
		case "open":
			var flag uint32
			json.Unmarshal(x["fflag"], &flag)
			switch {
			case flag&0x1 != 0: // FREAD
				add(Read, pathOf(x["file"]), "")
			case flag&0x2 != 0: // FWRITE alone: what ransomware and wipers ask for
				add(Write, pathOf(x["file"]), "")
			}
		case "clone", "copyfile":
			add(Read, pathOf(x["source"]), "")
		case "link":
			var dir file
			var name string
			json.Unmarshal(x["target_dir"], &dir)
			json.Unmarshal(x["target_filename"], &name)
			add(Link, pathOf(x["source"]), join(dir.Path, name))
		case "rename":
			add(Delete, pathOf(x["source"]), renameTarget(x["destination"]))
		case "unlink":
			add(Delete, pathOf(x["target"]), "")
		case "exchangedata":
			// Swapping a bait's contents with another file's: a read of it.
			add(Read, pathOf(x["file1"]), pathOf(x["file2"]))
			add(Read, pathOf(x["file2"]), pathOf(x["file1"]))
		}
	}
	return out
}

func pathOf(raw json.RawMessage) string {
	var f file
	if len(raw) == 0 || json.Unmarshal(raw, &f) != nil {
		return ""
	}
	return f.Path
}

func renameTarget(raw json.RawMessage) string {
	var d struct {
		Existing *file `json:"existing_file"`
		New      *struct {
			Dir      file   `json:"dir"`
			Filename string `json:"filename"`
		} `json:"new_path"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return ""
	}
	if d.Existing != nil {
		return d.Existing.Path
	}
	if d.New != nil {
		return join(d.New.Dir.Path, d.New.Filename)
	}
	return ""
}

func join(dir, name string) string {
	if dir == "" || name == "" {
		return ""
	}
	return strings.TrimSuffix(dir, "/") + "/" + name
}

// needlesFold is needles for the paths as written and in lower case (an
// alias is kept in lower case).
func needlesFold(paths []string) [][]byte {
	var all []string
	for _, p := range paths {
		all = append(all, p)
		if l := strings.ToLower(p); l != p {
			all = append(all, l)
		}
	}
	return needles(all)
}

// needles turns bait paths into the byte strings to look for in a raw line,
// so that only lines about a bait are ever read as JSON. JSON may write "/"
// as "\/", so both spellings are searched. File names are compared as
// written: macOS hands eslogger the name the file has on disk.
func needles(paths []string) [][]byte {
	var n [][]byte
	for _, p := range paths {
		q, _ := json.Marshal(p)
		plain := q[1 : len(q)-1]
		n = append(n, append([]byte(nil), plain...))
		if esc := bytes.ReplaceAll(plain, []byte("/"), []byte(`\/`)); !bytes.Equal(esc, plain) {
			n = append(n, esc)
		}
	}
	return n
}

// matcher finds any of a set of needles in a line in about one pass, not
// one per needle: needles are grouped by their first bytes (bait and store
// paths nearly all start with the home folder), each group's first bytes
// are searched for once, and only where they occur are the needles compared.
type matcher struct {
	groups []group
}

type group struct {
	anchor []byte
	rest   [][]byte // each needle, past the anchor
}

const anchorLen = 10

func newMatcher(ns [][]byte) *matcher {
	m := &matcher{}
	idx := map[string]int{}
	for _, n := range ns {
		k := len(n)
		if k > anchorLen {
			k = anchorLen
		}
		a := string(n[:k])
		i, ok := idx[a]
		if !ok {
			i = len(m.groups)
			idx[a] = i
			m.groups = append(m.groups, group{anchor: []byte(a)})
		}
		m.groups[i].rest = append(m.groups[i].rest, n[k:])
	}
	return m
}

func (m *matcher) match(line []byte) bool {
	if m == nil {
		return false
	}
	for _, g := range m.groups {
		for off := 0; off < len(line); {
			i := bytes.Index(line[off:], g.anchor)
			if i < 0 {
				break
			}
			at := off + i + len(g.anchor)
			for _, r := range g.rest {
				if bytes.HasPrefix(line[at:], r) {
					return true
				}
			}
			off += i + 1
		}
	}
	return false
}

func matchAny(line []byte, ns [][]byte) bool {
	for _, n := range ns {
		if bytes.Contains(line, n) {
			return true
		}
	}
	return false
}
