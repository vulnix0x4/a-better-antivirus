// Package netrec is ABA's network record: a small note, kept in memory, of
// which programs sent something over the network, where to, when and roughly
// how much.
//
// Like the flight recorder (package recorder) it never raises an alert and
// never acts, and it isn't detection: it's read only after a catch, by the
// autopsy (package autopsy), to answer "did anything leave this PC before ABA
// froze it?". That answer is only worth something if the record was running
// the whole time that matters and lost nothing, so it keeps track of that
// too: when it began, and every moment it may have missed something.
//
// What it keeps is bounded: per process, the addresses it sent to (at most
// maxDests, the rest counted together), a few bursts of sending per address,
// and its parent, so what a program started is found too. Processes are
// forgotten a while after they exit (keepExited).
//
// How sends are noticed is up to each operating system's watcher (Windows'
// own event tracing, in watch_windows.go); they all report here.
package netrec

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Limits on what's kept.
const (
	maxDests    = 64          // addresses kept per process; sends to more are counted together
	maxBursts   = 8           // bursts kept per address; older ones are merged into one
	burstGap    = time.Second // sends to one address this far apart start a new burst
	maxProcs    = 20000       // processes kept at most (most never send anything)
	keepExited  = 3 * time.Hour
	maxNames    = 4096 // DNS answers kept for naming addresses
	maxProcName = 32   // per process
	// exitSlack: what a process sent is still flushed out by the system a
	// moment after it exits.
	exitSlack = 2 * time.Second
	// sameStart is how far apart two reports of one start time may be.
	sameStart = time.Second
)

// Lapse is a stretch of time the record may have missed sends in.
type Lapse struct {
	From, To time.Time
	Why      string
}

type burst struct {
	from, to time.Time
	bytes    int64
}

// lookup is a name a process looked up, and when.
type lookup struct {
	name string
	at   time.Time
}

// maxLookups is how many names are kept per address of one process.
const maxLookups = 4

type dest struct {
	addr        netip.AddrPort // the zero AddrPort: "other addresses" (more than maxDests)
	udp         bool
	first, last time.Time
	bytes       int64
	sends       int
	conns       int
	bursts      []burst
	older       *burst // the bursts merged to stay within maxBursts
}

type proc struct {
	pid, ppid   uint32
	start, exit time.Time // start zero: unknown (the record never heard it start)
	image       string
	dests       map[netip.AddrPort]*dest
	other       *dest
	// names are the names it looked up, per address, with when: one
	// address can serve many names (a CDN), and the one it looked up just
	// before connecting is the one it meant.
	names       map[netip.Addr][]lookup
	first, last time.Time // its first and last activity
}

// Record is safe for concurrent use.
type Record struct {
	mu     sync.Mutex
	procs  map[uint32][]*proc // by PID, oldest first
	nprocs int
	began  time.Time // when the record began, unbroken since; zero: not running
	why    string    // why it isn't running
	lapses []Lapse
	// forgot: what happened before this may be gone (a process forgotten
	// to stay within the limits).
	forgot time.Time
	names  map[netip.Addr]string
	old    map[netip.Addr]string // the previous generation of names
	// catchUp, set by the watcher, waits until everything that happened up
	// to now has reached the record; false if it couldn't make sure.
	catchUp func(timeout time.Duration) bool
	now     func() time.Time
}

// New makes an empty record. It isn't running until Began says so.
func New() *Record {
	return &Record{procs: map[uint32][]*proc{}, names: map[netip.Addr]string{}, now: time.Now, why: "it hasn't started"}
}

// Began says the record is running, unbroken, from at on. catchUp (may be
// nil) is how the autopsy makes sure what happened up to now has come in.
func (r *Record) Began(at time.Time, catchUp func(time.Duration) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.began, r.why, r.catchUp = at, "", catchUp
}

// Stopped says the record isn't running from at on, and why.
func (r *Record) Stopped(at time.Time, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.began.IsZero() {
		r.lapses = append(r.lapses, Lapse{From: at, To: at, Why: why})
	}
	r.began, r.why, r.catchUp = time.Time{}, why, nil
}

// Lost says sends between from and to may have been missed.
func (r *Record) Lost(from, to time.Time, why string) {
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

// Started records that a process started (or was already running when the
// record began).
func (r *Record) Started(pid, ppid uint32, start time.Time, image string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.procs[pid] {
		if !p.start.IsZero() && near(p.start, start) {
			if p.image == "" {
				p.image = image
			}
			return // heard twice (a start event and the first look around)
		}
		if p.start.IsZero() && p.exit.IsZero() && !p.first.Before(start.Add(-sameStart)) {
			// Its sends came in before its start (the system's reports can
			// arrive out of order): the same process.
			p.ppid, p.start, p.image = ppid, start, image
			return
		}
	}
	r.add(&proc{pid: pid, ppid: ppid, start: start, image: image, first: start, last: start})
}

// Exited records that a process exited.
func (r *Record) Exited(pid uint32, start, exit time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.find(pid, exit, start); p != nil && p.exit.IsZero() {
		p.exit = exit
		if exit.After(p.last) {
			p.last = exit
		}
	}
}

// Send records that pid sent bytes to remote at at. conn: it's the start of
// a connection, not data (bytes is 0 then). Sends that stay on this PC, or go
// to no one device (multicast, broadcast), aren't kept.
func (r *Record) Send(at time.Time, pid uint32, remote netip.AddrPort, bytes int, conn, udp bool) {
	if Ignored(remote.Addr()) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.find(pid, at, time.Time{})
	if p == nil {
		p = &proc{pid: pid, first: at, last: at}
		r.add(p)
	}
	if at.After(p.last) {
		p.last = at
	}
	if at.Before(p.first) {
		p.first = at
	}
	if p.dests == nil {
		p.dests = map[netip.AddrPort]*dest{}
	}
	d := p.dests[remote]
	if d == nil {
		if len(p.dests) >= maxDests {
			if p.other == nil {
				p.other = &dest{}
			}
			d = p.other
		} else {
			d = &dest{addr: remote, udp: udp}
			p.dests[remote] = d
		}
	}
	d.add(at, int64(bytes), conn)
}

func (d *dest) add(at time.Time, bytes int64, conn bool) {
	if d.first.IsZero() || at.Before(d.first) {
		d.first = at
	}
	if at.After(d.last) {
		d.last = at
	}
	if conn {
		d.conns++
	} else {
		d.sends++
		d.bytes += bytes
	}
	if n := len(d.bursts); n > 0 {
		b := &d.bursts[n-1]
		if !at.Before(b.from) && at.Sub(b.to) <= burstGap {
			if at.After(b.to) {
				b.to = at
			}
			b.bytes += bytes
			return
		}
	}
	d.bursts = append(d.bursts, burst{from: at, to: at, bytes: bytes})
	sort.Slice(d.bursts, func(i, j int) bool { return d.bursts[i].from.Before(d.bursts[j].from) })
	if len(d.bursts) > maxBursts {
		b := d.bursts[0]
		if d.older == nil {
			d.older = &burst{from: b.from, to: b.to}
		}
		if b.from.Before(d.older.from) {
			d.older.from = b.from
		}
		if b.to.After(d.older.to) {
			d.older.to = b.to
		}
		d.older.bytes += b.bytes
		d.bursts = append(d.bursts[:0], d.bursts[1:]...)
	}
}

// Resolved records the addresses a name resolved to, for pid.
func (r *Record) Resolved(at time.Time, pid uint32, name string, addrs []netip.Addr) {
	if name == "" || len(addrs) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range addrs {
		a = a.Unmap()
		if len(r.names) >= maxNames {
			r.old, r.names = r.names, map[netip.Addr]string{}
		}
		r.names[a] = name
	}
	if p := r.find(pid, at, time.Time{}); p != nil {
		if p.names == nil {
			p.names = map[netip.Addr][]lookup{}
		}
		for _, a := range addrs {
			a = a.Unmap()
			l, ok := p.names[a]
			if !ok && len(p.names) >= maxProcName {
				continue
			}
			if n := len(l); n > 0 && l[n-1].name == name {
				continue // looked up again
			}
			l = append(l, lookup{name: name, at: at})
			if len(l) > maxLookups {
				l = l[1:]
			}
			p.names[a] = l
		}
	}
}

// find is the process pid that was running at at (and started at start, if
// that's known).
func (r *Record) find(pid uint32, at, start time.Time) *proc {
	list := r.procs[pid]
	for i := len(list) - 1; i >= 0; i-- {
		p := list[i]
		if !start.IsZero() && !p.start.IsZero() {
			if near(p.start, start) {
				return p
			}
			continue
		}
		if !p.start.IsZero() && at.Before(p.start.Add(-sameStart)) {
			continue
		}
		if !p.exit.IsZero() && at.After(p.exit.Add(exitSlack)) {
			continue
		}
		return p
	}
	return nil
}

func (r *Record) add(p *proc) {
	r.procs[p.pid] = append(r.procs[p.pid], p)
	r.nprocs++
	if r.nprocs > maxProcs {
		r.trim(maxProcs * 9 / 10)
	}
}

// trim forgets exited processes, longest gone first, until at most n are
// left, and remembers that what happened before then may be gone.
func (r *Record) trim(n int) {
	var gone []*proc
	for _, list := range r.procs {
		for _, p := range list {
			if !p.exit.IsZero() || p.start.IsZero() {
				gone = append(gone, p)
			}
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].last.Before(gone[j].last) })
	for _, p := range gone {
		if r.nprocs <= n {
			break
		}
		r.forget(p)
	}
}

func (r *Record) forget(p *proc) {
	list := r.procs[p.pid]
	for i, x := range list {
		if x == p {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(r.procs, p.pid)
	} else {
		r.procs[p.pid] = list
	}
	r.nprocs--
	if p.last.After(r.forgot) {
		r.forgot = p.last
	}
}

// Prune forgets processes that exited more than keepExited ago (and those
// never heard to start or exit, quiet as long); the service calls it now
// and then.
func (r *Record) Prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var old []*proc
	for _, list := range r.procs {
		for _, p := range list {
			if (!p.exit.IsZero() || p.start.IsZero()) && now.Sub(p.last) > keepExited {
				old = append(old, p)
			}
		}
	}
	for _, p := range old {
		r.forget(p)
	}
	keep := r.lapses[:0]
	for _, l := range r.lapses {
		if now.Sub(l.To) < 24*time.Hour {
			keep = append(keep, l)
		}
	}
	r.lapses = keep
}

// Ignored says whether a send to a stays on this PC (loopback, which is also
// where the miner trap's fake pool lives) or goes to no one device in
// particular (multicast, broadcast): those never count as leaving it.
func Ignored(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsValid() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsLinkLocalMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// LocalNetwork says whether a is on a local network (a router, a printer, a
// proxy): it left this PC, but maybe not the building.
func LocalNetwork(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

func near(a, b time.Time) bool {
	d := a.Sub(b)
	return d > -sameStart && d < sameStart
}

// Status is how the record is doing, for `aba doctor`.
type Status struct {
	Running bool
	Since   time.Time
	Why     string
	Procs   int
	Sending int // processes it has sends of
}

// Status summarises the record.
func (r *Record) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{Running: !r.began.IsZero(), Since: r.began, Why: r.why, Procs: r.nprocs}
	for _, list := range r.procs {
		for _, p := range list {
			if len(p.dests) > 0 || p.other != nil {
				st.Sending++
			}
		}
	}
	return st
}
