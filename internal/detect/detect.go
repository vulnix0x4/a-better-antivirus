// Package detect is the shape of what a watcher tells the engine: "this
// program touched that bait". It says nothing about how the operating system
// noticed, which differs a lot:
//
//   - Windows: an oplock on every bait (package instant) pauses the opener
//     inside its open, and the Security event log (package evtlog) reports the
//     read a moment later, as a backup.
//   - Linux: fanotify permission events pause the opener and name it.
//   - macOS: Endpoint Security (or eslogger) may only report the open after it
//     happened.
//
// So a watcher talks to the engine in one of two ways, depending on whether
// the opener is being held at that moment:
//
//   - Held (it's paused inside the open and can't read yet): ask
//     engine.DecideInstant whether it should be frozen now. If so, freeze it,
//     let the open go through and report with engine.HandleOpen, passing what
//     was frozen. If not, let it through; unless another watcher will report
//     the read anyway, report it with engine.HandleAccess.
//   - Not held (the access already happened): report an Access with
//     engine.HandleAccess. The engine freezes the program itself if its verdict
//     calls for it.
package detect

import "time"

// Op is what was done to the bait.
type Op int

const (
	// OpRead: opened to get at its contents (reading, or mapping or executing
	// it, which reads without asking for read access).
	OpRead Op = iota + 1
	// OpDelete: deleted, or renamed away.
	OpDelete
	// OpSwap: replaced the wallet address ABA put on the clipboard with
	// another one: a clipper (see package clipbait). Path is empty and Swap
	// says what happened.
	OpSwap
	// OpWrite: opened to change its contents without reading them (overwrite,
	// truncate, append). Nothing has a reason to rewrite a bait; ransomware
	// and wipers rewrite everything.
	OpWrite
)

// Swap is what a clipper did to the clipboard bait.
type Swap struct {
	Coin        string // the kind of address the bait imitated
	Bait        string // the fake address ABA put on the clipboard
	Replacement string // what the program put there instead: the attacker's address ("" if it only wiped it)
	How         string // how the program was pinned down
	LatencyMS   int64  // how quickly it swapped
	Keyed       bool   // the bait was a real address whose key ABA holds
}

// Access is one program touching one bait.
type Access struct {
	Time time.Time // when it happened
	Op   Op
	// Path is the bait file. Alias is set when the program reached it under
	// another name (a hard link to the bait): the name it actually used.
	Path  string
	Alias string

	PID uint32
	// Image is the program's executable as the watcher reported it ("" if it
	// didn't). While the process is alive the engine asks the operating
	// system which file is really running, and goes by that.
	Image string
	// User is the account it ran as, for display. UserID is the same account
	// in the form procinfo.ServiceAccount takes (a SID on Windows): once the
	// process is gone, that's what tells a person's program from a service.
	User   string
	UserID string

	// Helpers are processes the operating system ran to do this program's
	// work for it (on macOS: Finder's helper copying a file a script asked
	// Finder to copy). They're frozen with the program when it's frozen as a
	// stealer, and left alone otherwise.
	Helpers []uint32

	Swap *Swap // OpSwap only
}
