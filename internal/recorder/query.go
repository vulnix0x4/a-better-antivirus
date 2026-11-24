package recorder

import (
	"fmt"
	"sort"
	"time"
)

// Member is one process of the program being looked into: the one caught
// and those that belong to it (what it started, what started it and was
// frozen with it).
type Member struct {
	PID   uint32
	Start time.Time // when it started; zero if unknown (it had exited)
	Image string
}

// Query asks about the members, between From (when the first of them
// started) and To (now: they're frozen, they can't open anything more).
type Query struct {
	Members  []Member
	From, To time.Time
}

// Read is a real store's file one of the members opened, for certain.
type Read struct {
	Store, StoreName, Kind string
	Path                   string
	First, Last            time.Time
	Count                  int
	PID                    uint32
	Image                  string
	// Via says how it's known to be one of them when it's not a member
	// itself: "started by pid 812" (a helper that has exited since).
	Via string
}

// Doubt is an open that may have been one of the members', but can't be
// pinned on them for certain.
type Doubt struct {
	Store, StoreName string
	Path             string
	At               time.Time
	PID              uint32
	Why              string
}

// Coverage is how well one store was watched over the query's time.
type Coverage struct {
	Store, Name, Kind string
	Files             int
	Absent            bool      // no such files on this computer
	Watched           bool      // watched the whole time, every file
	Since             time.Time // watched without a break since then (zero: not watched now)
	Why               string    // why not the whole time, when it wasn't
}

// Result is what the recorder can say.
type Result struct {
	Reads  []Read
	Doubts []Doubt
	Stores []Coverage
	Lapses []Lapse // moments in the time asked about when opens may have been missed
	// Forgot is set when opens from part of the time asked about may have
	// been dropped (the recorder keeps a day, and only so many).
	Forgot time.Time
}

// slack is how close to a process's start an open can be and still not be
// told apart from the program that had its number before: timestamps come
// from different clocks in the operating system, rounded differently.
const slack = 50 * time.Millisecond

// sameStart is how far apart two reports of one start time may be.
const sameStart = time.Second

type verdict int

const (
	notMine verdict = iota
	mine
	unsure
)

// attribute says whether e was opened by one of members, and if so which.
func attribute(e *entry, members []Member) (v verdict, m Member, via, why string) {
	if e.PID == 0 {
		return unsure, Member{}, "", "the system couldn't say which program opened it"
	}
	for _, x := range members {
		if x.PID != e.PID {
			continue
		}
		switch {
		case !e.Start.IsZero() && !x.Start.IsZero():
			if d := e.Start.Sub(x.Start); d > -sameStart && d < sameStart {
				return mine, x, "", ""
			}
			continue // another process that had the same number
		case x.Start.IsZero():
			return unsure, x, "", fmt.Sprintf("process %d had exited by the time ABA looked, so it can't be sure no other program had that number then", e.PID)
		case !e.last.Before(x.Start.Add(slack)):
			return mine, x, "", ""
		case e.last.Before(x.Start.Add(-slack)):
			continue
		default:
			return unsure, x, "", fmt.Sprintf("opened within a moment of process %d starting, too close to tell it from the program that had that number before", e.PID)
		}
	}
	if e.PPID == 0 {
		return notMine, Member{}, "", ""
	}
	for _, x := range members {
		if x.PID != e.PPID {
			continue
		}
		switch {
		case x.Start.IsZero():
			return unsure, x, "", fmt.Sprintf("opened by a program process %d started, which had exited by the time ABA looked", e.PPID)
		case !e.first.Before(x.Start.Add(slack)):
			return mine, x, fmt.Sprintf("started by pid %d", x.PID), ""
		}
	}
	return notMine, Member{}, "", ""
}

// Query answers q. It never guesses: an open is in Reads only if it was
// certainly one of the members'.
func (r *Recorder) Query(q Query) Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	var res Result
	names := map[string]*cover{}
	for id, c := range r.covers {
		names[id] = c
	}
	in := func(t time.Time) bool { return !t.Before(q.From.Add(-slack)) && !t.After(q.To) }
	for _, e := range r.byKey {
		if !in(e.last) && !in(e.first) {
			continue
		}
		c := names[e.store]
		name, kind := e.store, ""
		if c != nil {
			name, kind = c.store.Name, c.store.Kind
		}
		v, m, via, why := attribute(e, q.Members)
		switch v {
		case mine:
			first := e.first
			if !m.Start.IsZero() && first.Before(m.Start) {
				first = e.last // the earlier ones were another program's with the same number
			}
			img := e.Image
			if img == "" {
				img = m.Image
			}
			res.Reads = append(res.Reads, Read{Store: e.store, StoreName: name, Kind: kind, Path: e.Path, First: first, Last: e.last,
				Count: e.count, PID: e.PID, Image: img, Via: via})
		case unsure:
			res.Doubts = append(res.Doubts, Doubt{Store: e.store, StoreName: name, Path: e.Path, At: e.first, PID: e.PID, Why: why})
		}
	}
	sort.Slice(res.Reads, func(i, j int) bool { return res.Reads[i].First.Before(res.Reads[j].First) })
	sort.Slice(res.Doubts, func(i, j int) bool { return res.Doubts[i].At.Before(res.Doubts[j].At) })

	for _, s := range r.stores {
		c := r.covers[s.ID]
		cv := Coverage{Store: s.ID, Name: s.Name, Kind: s.Kind}
		if c == nil {
			cv.Why = "ABA wasn't watching it"
			res.Stores = append(res.Stores, cv)
			continue
		}
		cv.Files = c.files
		if n := len(c.spans); n > 0 && c.spans[n-1].to.IsZero() {
			cv.Since = c.spans[n-1].from
		}
		for _, sp := range c.spans {
			if !sp.from.After(q.From) && (sp.to.IsZero() || !sp.to.Before(q.To)) {
				cv.Watched = true
			}
		}
		switch {
		case cv.Watched:
		case c.why == absent && len(c.spans) == 0:
			cv.Absent = true
		case c.why == absent:
			cv.Absent = true // there at some point, gone now: say so if it was read
			cv.Why = "its files are gone now"
		case !cv.Since.IsZero():
			cv.Why = "ABA only started watching it at " + cv.Since.Format("15:04:05") + ", after the program started"
		case c.why != "":
			cv.Why = c.why
		default:
			cv.Why = "ABA wasn't watching it"
		}
		res.Stores = append(res.Stores, cv)
	}
	sort.Slice(res.Stores, func(i, j int) bool { return res.Stores[i].Name < res.Stores[j].Name })

	for _, l := range r.lapses {
		if !l.To.Before(q.From) && !l.From.After(q.To) {
			res.Lapses = append(res.Lapses, l)
		}
	}
	if r.forgot.After(q.From) {
		res.Forgot = r.forgot
	}
	return res
}

// Status is how the recorder is doing, for `aba doctor` and the autopsy.
type Status struct {
	Stores, Watched, Absent int
	Entries                 int
	Oldest                  time.Time
}

// Status summarises the recorder.
func (r *Recorder) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{Stores: len(r.stores), Entries: len(r.byKey)}
	for _, s := range r.stores {
		c := r.covers[s.ID]
		if c == nil {
			continue
		}
		if n := len(c.spans); n > 0 && c.spans[n-1].to.IsZero() {
			st.Watched++
			if st.Oldest.IsZero() || c.spans[n-1].from.Before(st.Oldest) {
				st.Oldest = c.spans[n-1].from
			}
		} else if c.why == absent {
			st.Absent++
		}
	}
	return st
}
