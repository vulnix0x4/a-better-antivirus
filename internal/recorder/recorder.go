// Package recorder is ABA's flight recorder: a quiet note, kept in memory,
// of every open of your real passwords, cookies, wallets and keys (the real
// counterparts of the baits, see baits.RealStores), and of which process made
// it.
//
// It never raises an alert and never acts. It's read only after a catch:
// when a program has tripped a bait and is frozen, the autopsy (package
// autopsy) asks it "did this program, or anything it started, open any of
// the real things, and could you have seen it if it had?". The second half
// matters as much as the first: an answer of "nothing" is only worth
// something if the recorder was watching that store, for the whole time the
// program ran, and could name every opener.
//
// How opens are noticed is up to each operating system's watcher (the
// Security log on Windows, fanotify on Linux, eslogger on macOS); they all
// report here, in the same form.
package recorder

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
)

// Open is one open of a real store's file, as a watcher reported it.
type Open struct {
	At    time.Time // when it happened (the operating system's timestamp)
	Path  string
	PID   uint32 // 0: the operating system couldn't say who
	PPID  uint32 // its parent at the time, 0 if unknown
	Start time.Time
	// Start is when the opener started, as the operating system said at the
	// time: with the PID it names the process for good. Zero if unknown.
	Image string // its executable, as reported ("" if not)
}

// entry is what's kept: one process's opens of one file.
type entry struct {
	Open
	first, last time.Time
	count       int
	store       string
	key         string
}

// span is a stretch of time a store was watched.
type span struct{ from, to time.Time } // to zero: still watched

// cover is what the recorder knows about watching one store.
type cover struct {
	store baits.Store
	spans []span
	why   string // why it isn't watched now ("" if it is, or was never asked to be)
	files int    // how many of its files were being watched last time
}

// Lapse is a moment the recorder may have missed opens of every store: the
// operating system dropped events, or the watcher stopped.
type Lapse struct {
	From, To time.Time
	Why      string
}

// maxEntries bounds what's kept: one entry per process and file, so a
// browser opening its own cookies all day is one entry.
const maxEntries = 20000

// splitAfter: opens by the same PID this far apart, with no start time to
// tell processes apart, are kept as separate entries.
const splitAfter = 10 * time.Minute

// keepFor is how long opens are kept.
const keepFor = 24 * time.Hour

// Recorder is safe for concurrent use.
type Recorder struct {
	mu     sync.Mutex
	stores []baits.Store
	isBait func(path string) bool
	covers map[string]*cover
	byKey  map[string]*entry
	lapses []Lapse
	// forgot is the moment before which opens may have been dropped to
	// stay within maxEntries or keepFor.
	forgot time.Time
	now    func() time.Time
}

// New makes an empty recorder; it watches nothing until SetStores and
// Watching say so.
func New() *Recorder {
	return &Recorder{covers: map[string]*cover{}, byKey: map[string]*entry{}, now: time.Now}
}

// SetStores sets which real stores there are. isBait says whether a path is
// a bait (a bait profile inside a real browser is in the same folder as the
// real one): those are never recorded here, the bait watchers have them.
func (r *Recorder) SetStores(stores []baits.Store, isBait func(string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stores = append([]baits.Store(nil), stores...)
	r.isBait = isBait
	now := r.now()
	keep := map[string]bool{}
	for _, s := range stores {
		keep[s.ID] = true
		if c := r.covers[s.ID]; c != nil {
			c.store = s
		} else {
			r.covers[s.ID] = &cover{store: s}
		}
	}
	for id, c := range r.covers {
		if !keep[id] {
			c.close(now, "it's no longer one of your stores")
		}
	}
}

// Stores lists the real stores.
func (r *Recorder) Stores() []baits.Store {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]baits.Store(nil), r.stores...)
}

// Match says which store path is a file of (never a bait).
func (r *Recorder) Match(path string) (baits.Store, bool) {
	r.mu.Lock()
	stores, isBait := r.stores, r.isBait
	r.mu.Unlock()
	if isBait != nil && isBait(path) {
		return baits.Store{}, false
	}
	return baits.StoreFor(stores, path)
}

func (c *cover) open(at time.Time) {
	if n := len(c.spans); n > 0 && c.spans[n-1].to.IsZero() {
		return
	}
	c.spans = append(c.spans, span{from: at})
	c.why = ""
}

func (c *cover) close(at time.Time, why string) {
	if n := len(c.spans); n > 0 && c.spans[n-1].to.IsZero() {
		c.spans[n-1].to = at
	}
	c.why = why
}

// Watching says a store's files are all being watched from at on (files:
// how many). Saying it again changes nothing.
func (r *Recorder) Watching(storeID string, files int, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.covers[storeID]
	if c == nil {
		return
	}
	c.files = files
	c.open(at)
}

// NotWatching says a store is not (fully) watched from at on, and why. The
// watcher says so as soon as it knows: a file it couldn't watch, a watch
// that was found gone (then at is when it was last seen in place).
func (r *Recorder) NotWatching(storeID string, at time.Time, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.covers[storeID]; c != nil {
		c.close(at, why)
	}
}

// Absent says a store has no files on this computer (the app isn't there,
// or not used yet). Nothing to watch, and nothing to steal.
func (r *Recorder) Absent(storeID string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.covers[storeID]; c != nil {
		c.close(at, absent)
		c.files = 0
	}
}

const absent = "absent"

// Lost says opens of any store may have been missed between from and to
// (the operating system dropped events, the watcher was restarting).
func (r *Recorder) Lost(from, to time.Time, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.lapses); n > 0 && r.lapses[n-1].Why == why && !from.After(r.lapses[n-1].To.Add(time.Second)) {
		if to.After(r.lapses[n-1].To) {
			r.lapses[n-1].To = to
		}
		return
	}
	r.lapses = append(r.lapses, Lapse{From: from, To: to, Why: why})
	if len(r.lapses) > 1000 {
		r.lapses = r.lapses[len(r.lapses)-1000:]
	}
}

// Note records an open. One that isn't of a real store is ignored.
func (r *Recorder) Note(o Open) {
	s, ok := r.Match(o.Path)
	if !ok {
		return
	}
	r.NoteStore(s.ID, o)
}

// NoteStore records an open of storeID's file (the watcher already matched it).
func (r *Recorder) NoteStore(storeID string, o Open) {
	if o.At.IsZero() {
		o.At = r.now()
	}
	key := strings.Join([]string{storeID, o.Path, itoa(o.PID), itoa(uint32(o.Start.Unix())), itoa(o.PPID)}, "|")
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.byKey[key]; e != nil && o.Start.IsZero() && o.At.Sub(e.last) > splitAfter {
		// Without a start time the PID alone doesn't say it's the same
		// process as before: keep the earlier opens apart.
		delete(r.byKey, key)
		e.key = key + "#" + e.first.Format(time.RFC3339Nano)
		r.byKey[e.key] = e
	}
	if e := r.byKey[key]; e != nil {
		e.count++
		if o.At.Before(e.first) {
			e.first = o.At
		}
		if o.At.After(e.last) {
			e.last = o.At
		}
		if e.Image == "" {
			e.Image = o.Image
		}
		return
	}
	r.byKey[key] = &entry{Open: o, first: o.At, last: o.At, count: 1, store: storeID, key: key}
	if len(r.byKey) > maxEntries {
		r.trim()
	}
}

// trim drops the oldest entries (and anything older than keepFor), and
// remembers that opens from before then may be gone.
func (r *Recorder) trim() {
	now := r.now()
	all := make([]*entry, 0, len(r.byKey))
	for _, e := range r.byKey {
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	drop := len(all) - maxEntries*9/10
	for i, e := range all {
		if i >= drop && now.Sub(e.last) < keepFor {
			break
		}
		if e.last.After(r.forgot) {
			r.forgot = e.last
		}
		delete(r.byKey, e.key)
	}
}

// Prune drops what's older than keepFor; the service calls it now and then.
func (r *Recorder) Prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for k, e := range r.byKey {
		if now.Sub(e.last) > keepFor {
			if e.last.After(r.forgot) {
				r.forgot = e.last
			}
			delete(r.byKey, k)
		}
	}
	for _, c := range r.covers {
		var keep []span
		for _, s := range c.spans {
			if s.to.IsZero() || now.Sub(s.to) < keepFor {
				keep = append(keep, s)
			}
		}
		c.spans = keep
	}
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
