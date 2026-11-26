package netrec

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// Member is one process of the program being looked into (the one caught,
// and those frozen with it). What they started is found by the record.
type Member struct {
	PID   uint32
	Start time.Time // zero if unknown (it had exited)
}

// Query asks what the members, and everything they started, sent between
// From and To.
type Query struct {
	Members  []Member
	From, To time.Time
}

// Send is what one process sent to one address over the time asked about.
type Send struct {
	PID   uint32
	Image string
	// Via says how it's known to be part of the program when it isn't a
	// member itself: "started by pid 812".
	Via    string
	Remote netip.AddrPort // the zero AddrPort: more addresses than the record keeps apart
	Name   string         // the name it was looked up by, if the record saw that
	UDP    bool
	LAN    bool // on a local network (see LocalNetwork)
	First  time.Time
	Last   time.Time
	Bytes  int64
	Sends  int
	Conns  int // connections it opened
	bursts []burst
}

// Since says whether it sent anything at t or later (a connection opened
// counts), and roughly how much: a burst that began before t is counted
// whole.
func (s Send) Since(t time.Time) (bytes int64, any bool) {
	if s.Last.Before(t) {
		return 0, false
	}
	for _, b := range s.bursts {
		if !b.to.Before(t) {
			bytes += b.bytes
			any = true
		}
	}
	return bytes, any
}

// Where is the address in words: "discord.com (162.159.135.232:443)".
func (s Send) Where() string {
	if !s.Remote.IsValid() {
		return "other addresses"
	}
	a := s.Remote.String()
	if s.Name != "" {
		return s.Name + " (" + a + ")"
	}
	return a
}

// Host is the name, or the address without its port.
func (s Send) Host() string {
	switch {
	case s.Name != "":
		return s.Name
	case s.Remote.IsValid():
		return s.Remote.Addr().String()
	}
	return "other addresses"
}

// Result is what the record can say.
type Result struct {
	Running bool
	Why     string    // why it isn't running
	Began   time.Time // running unbroken since
	// Lapses are moments in the time asked about when sends may have been
	// missed.
	Lapses []Lapse
	// Forgot is set when what happened in part of the time asked about may
	// be gone (processes forgotten to stay within the limits).
	Forgot time.Time
	// Behind is set when the record couldn't make sure the last moments had
	// reached it.
	Behind bool
	Sends  []Send
}

// catchUpWait is how long a query waits for the last moments to come in.
const catchUpWait = 4 * time.Second

// Query answers q. It never guesses: a send is listed only if it was
// certainly one of the members', or of what they started.
func (r *Record) Query(q Query) Result {
	r.mu.Lock()
	catchUp := r.catchUp
	r.mu.Unlock()
	behind := false
	if catchUp != nil && !catchUp(catchUpWait) {
		behind = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	res := Result{Running: !r.began.IsZero(), Why: r.why, Began: r.began, Behind: behind}
	for _, l := range r.lapses {
		if !l.To.Before(q.From) && !l.From.After(q.To) {
			res.Lapses = append(res.Lapses, l)
		}
	}
	if r.forgot.After(q.From) {
		res.Forgot = r.forgot
	}

	// The members' processes, and everything started by one of them.
	in := map[*proc]string{} // -> how it's theirs ("" if a member)
	from := map[*proc]time.Time{}
	member := func(p *proc) (time.Time, bool) {
		for _, m := range q.Members {
			if m.PID != p.pid {
				continue
			}
			switch {
			case !p.start.IsZero() && !m.Start.IsZero():
				if near(p.start, m.Start) {
					return p.start, true
				}
			case m.Start.IsZero():
				// The member had exited when the autopsy asked: only a
				// process the record knows the life of can be pinned on it,
				// and only if it lived in the time asked about.
				if !p.start.IsZero() && (p.exit.IsZero() || !p.exit.Before(q.From)) && !p.start.After(q.To) {
					return p.start, true
				}
			default:
				// Never heard to start: what it did once the member was
				// running is the member's (the number was free before).
				if !p.last.Before(m.Start) {
					return m.Start, true
				}
			}
		}
		return time.Time{}, false
	}
	for changed := true; changed; {
		changed = false
		for _, list := range r.procs {
			for _, p := range list {
				if _, ok := in[p]; ok {
					continue
				}
				if t, ok := member(p); ok {
					in[p], from[p] = "", t
					changed = true
					continue
				}
				if p.ppid == 0 || p.start.IsZero() {
					continue
				}
				parent := r.find(p.ppid, p.start, time.Time{})
				if parent == nil || parent == p {
					// Its parent isn't in the record: one of the members
					// still counts, if it was running then.
					for _, m := range q.Members {
						if m.PID == p.ppid && !m.Start.IsZero() && !p.start.Before(m.Start) {
							parent = &proc{pid: m.PID}
							in[parent] = ""
						}
					}
				}
				if parent != nil {
					if _, ok := in[parent]; ok {
						in[p], from[p] = fmt.Sprintf("started by pid %d", p.ppid), p.start
						changed = true
					}
				}
			}
		}
	}

	for p, via := range in {
		lo := q.From
		if t := from[p]; t.After(lo) {
			lo = t.Add(-sameStart)
		}
		add := func(d *dest) {
			s := Send{PID: p.pid, Image: p.image, Via: via, Remote: d.addr, UDP: d.udp}
			if d.addr.IsValid() {
				s.LAN = LocalNetwork(d.addr.Addr())
				s.Name = p.names[d.addr.Addr()]
				if s.Name == "" {
					s.Name = r.names[d.addr.Addr()]
				}
				if s.Name == "" {
					s.Name = r.old[d.addr.Addr()]
				}
			}
			bs := d.bursts
			if d.older != nil {
				bs = append([]burst{*d.older}, bs...)
			}
			for _, b := range bs {
				if b.to.Before(lo) || b.from.After(q.To) {
					continue
				}
				s.bursts = append(s.bursts, b)
				s.Bytes += b.bytes
				if s.First.IsZero() || b.from.Before(s.First) {
					s.First = b.from
				}
				if b.to.After(s.Last) {
					s.Last = b.to
				}
			}
			if len(s.bursts) == 0 {
				return
			}
			if s.First.Before(lo) {
				s.First = lo
			}
			if s.Bytes == d.bytes || len(s.bursts) == len(bs) {
				s.Sends, s.Conns = d.sends, d.conns
			}
			res.Sends = append(res.Sends, s)
		}
		for _, d := range p.dests {
			add(d)
		}
		if p.other != nil {
			add(p.other)
		}
	}
	sort.Slice(res.Sends, func(i, j int) bool {
		if !res.Sends[i].First.Equal(res.Sends[j].First) {
			return res.Sends[i].First.Before(res.Sends[j].First)
		}
		return res.Sends[i].Remote.String() < res.Sends[j].Remote.String()
	})
	return res
}
