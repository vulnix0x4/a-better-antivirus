// Package instant catches a bait reader the moment it opens a bait.
//
// How it works, without a kernel driver:
//
//  1. ABA holds an exclusive opportunistic lock (oplock) on every bait file.
//  2. When another program opens the bait, Windows pauses that program inside
//     its "open file" call and tells ABA immediately (an oplock break).
//  3. Windows doesn't say who opened it, so ABA notes the threads whose kernel
//     wait began at that moment and are still stuck a few ms later.
//  4. ABA lets go. The opener wakes at that exact instant; an innocent thread
//     that happened to get stuck at the same time (e.g. reading a pipe) does
//     not. Whoever woke is the opener, identified precisely.
//  5. The service applies the usual verdict and freezes it a few ms after it
//     opened the bait, without waiting for the event log (0.2-1 s).
//
// (An earlier version froze candidates *before* releasing, so the reader got 0
// bytes, but CI showed that can freeze an innocent bystander. Precision wins.)
//
// A program can ask Windows not to pause it (FILE_COMPLETE_IF_OPLOCKED): its
// open returns at once, so no thread is ever stuck and step 3 finds nobody.
// That open does leave a handle behind, though, and Windows will say which
// programs hold a file open. So when nobody wakes, whoever newly holds the
// bait is the opener ("ghost open"). It can't read through that handle until
// ABA lets go, and asking not to be paused is itself a sign of evasion.
//
// The regular audit-log detection keeps running as a backup in case the
// opener couldn't be pinpointed.
package instant

import (
	"errors"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// ---- oplock guard on one file ----

const (
	fsctlRequestOplock = 0x00090240
	oplockRWH          = 0x7 // read | handle | write caching: any other open breaks it
	oplockFlagRequest  = 0x1
)

type oplockIn struct {
	Version, Length uint16
	Level, Flags    uint32
}

type oplockOut struct {
	Version, Length         uint16
	OriginalLevel, NewLevel uint32
	Flags, AccessMode       uint32
	ShareMode, _            uint16
}

// Guard holds an oplock on one file. Its event fires when someone opens it.
type Guard struct {
	Path  string
	h     windows.Handle
	event windows.Handle
	// Kept alive (and in place) while the request is pending in the kernel.
	ov  *windows.Overlapped
	in  *oplockIn
	out *oplockOut
	// Programs that already held the file open when the guard was armed
	// (attribute-only handles don't break an oplock): never the opener.
	before map[uint32]bool
}

// ErrNotGranted means another handle is open right now; try again later.
var ErrNotGranted = errors.New("oplock not granted (file is open elsewhere)")

// Arm opens path and requests an exclusive oplock. The open asks for read
// access but never reads, so it doesn't produce an audit event.
func Arm(path string) (*Guard, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Backup semantics: with the backup privilege (the service has it) the open
	// succeeds whatever the file's permissions say, so a program running as you
	// can't lock ABA out of a bait by rewriting them.
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	g := &Guard{Path: path, h: h, event: ev, ov: &windows.Overlapped{HEvent: ev},
		in:  &oplockIn{Version: 1, Length: uint16(unsafe.Sizeof(oplockIn{})), Level: oplockRWH, Flags: oplockFlagRequest},
		out: &oplockOut{}}
	err = windows.DeviceIoControl(h, fsctlRequestOplock,
		(*byte)(unsafe.Pointer(g.in)), uint32(unsafe.Sizeof(*g.in)),
		(*byte)(unsafe.Pointer(g.out)), uint32(unsafe.Sizeof(*g.out)), nil, g.ov)
	if err != windows.ERROR_IO_PENDING {
		windows.CloseHandle(h)
		windows.CloseHandle(ev)
		if err == nil {
			return nil, ErrNotGranted // completed immediately: not held
		}
		return nil, ErrNotGranted
	}
	g.before = map[uint32]bool{}
	for _, pid := range g.Users() {
		g.before[pid] = true
	}
	return g, nil
}

var procNtQueryInformationFile = ntdll.NewProc("NtQueryInformationFile")

const fileProcessIdsUsingFileInformation = 47

// Users lists the programs (PIDs) that have the file open right now, other
// than through this guard. It's what Explorer's "file is open in…" uses. A
// program paused inside its open isn't listed yet; one whose open already
// returned is.
func (g *Guard) Users() []uint32 {
	if g.h == 0 {
		return nil
	}
	buf := make([]byte, 8+8*64)
	for try := 0; try < 3; try++ {
		var iosb windows.IO_STATUS_BLOCK
		r, _, _ := procNtQueryInformationFile.Call(uintptr(g.h), uintptr(unsafe.Pointer(&iosb)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), fileProcessIdsUsingFileInformation)
		const statusInfoLengthMismatch, statusBufferOverflow = 0xC0000004, 0x80000005
		if uint32(r) == statusInfoLengthMismatch || uint32(r) == statusBufferOverflow {
			buf = make([]byte, len(buf)*8)
			continue
		}
		if r != 0 {
			return nil
		}
		n := int(le32(buf, 0))
		var out []uint32
		for i := 0; i < n && 8+8*(i+1) <= len(buf); i++ {
			out = append(out, uint32(le64(buf, 8+8*i)))
		}
		return out
	}
	return nil
}

// NewUsers are the programs holding the file open now that weren't when the
// guard was armed, leaving out self (ABA).
func (g *Guard) NewUsers(self uint32) []uint32 {
	var out []uint32
	for _, pid := range g.Users() {
		if pid != self && pid > 4 && !g.before[pid] {
			out = append(out, pid)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Event is signalled when another program opens the file.
func (g *Guard) Event() windows.Handle { return g.event }

// Release lets go: the paused opener's open completes.
func (g *Guard) Release() {
	if g.h != 0 {
		windows.CloseHandle(g.h)
		g.h = 0
	}
	if g.event != 0 {
		windows.CloseHandle(g.event)
		g.event = 0
	}
}

// ---- finding the opener ----

var ntdll = windows.NewLazySystemDLL("ntdll.dll")

// Thread is a thread currently blocked in a kernel ("Executive") wait.
type Thread struct {
	PID, TID    uint32
	WaitTime    uint32 // tick count when the wait began
	CtxSwitches uint32
}

// StuckThreads lists threads in an Executive wait, excluding PIDs 0, 4 and skip.
func StuckThreads(skip uint32) ([]Thread, error) {
	ps, err := procinfo.SystemProcesses(func(pid uint32) bool { return pid > 4 && pid != skip })
	if err != nil {
		return nil, err
	}
	var out []Thread
	for _, p := range ps {
		for _, t := range p.Threads {
			if t.State == procinfo.ThreadWaiting && t.WaitReason == procinfo.WaitExecutive {
				out = append(out, Thread{PID: t.PID, TID: t.TID, WaitTime: t.WaitTime, CtxSwitches: t.CtxSwitches})
			}
		}
	}
	return out, nil
}

func le32(b []byte, off int) uint32 { return *(*uint32)(unsafe.Pointer(&b[off])) }
func le64(b []byte, off int) uint64 { return *(*uint64)(unsafe.Pointer(&b[off])) }

var sharedTickAddr = uintptr(0x7FFE0320) // KUSER_SHARED_DATA.TickCount (low part), same clock as WaitTime

// Tick returns the kernel tick count (~15.6 ms per tick).
func Tick() uint32 { return **(**uint32)(unsafe.Pointer(&sharedTickAddr)) }

// FindStuck returns threads that got stuck at tick0 (the break) and are still
// stuck after settle. The opener is always among them, but so may be an
// innocent thread that happened to start a long wait (e.g. a pipe read) at the
// same moment, which is why Woke is used to tell them apart.
func FindStuck(tick0 uint32, skip uint32, settle time.Duration) []Thread {
	time.Sleep(settle / 3)
	s1, err := StuckThreads(skip)
	if err != nil {
		return nil
	}
	time.Sleep(settle - settle/3)
	s2, err := StuckThreads(skip)
	if err != nil {
		return nil
	}
	later := map[[2]uint32]Thread{}
	for _, t := range s2 {
		later[[2]uint32{t.PID, t.TID}] = t
	}
	var out []Thread
	for _, t := range s1 {
		if t.WaitTime+3 < tick0 || t.WaitTime > tick0+2 {
			continue // started waiting well before or after the open
		}
		if t2, ok := later[[2]uint32{t.PID, t.TID}]; ok && t2.WaitTime == t.WaitTime && t2.CtxSwitches == t.CtxSwitches {
			out = append(out, t) // still stuck in the very same wait
		}
	}
	return out
}

// Woke returns the PIDs of stuck threads that left their wait right after we
// released the oplock: the opener wakes at that exact moment, while innocent
// threads stuck on something else keep waiting.
func Woke(stuck []Thread, skip uint32, after time.Duration) []uint32 {
	if len(stuck) == 0 {
		return nil
	}
	time.Sleep(after)
	now, err := StuckThreads(skip)
	if err != nil {
		return nil
	}
	still := map[[2]uint32]Thread{}
	for _, t := range now {
		still[[2]uint32{t.PID, t.TID}] = t
	}
	pids := map[uint32]bool{}
	for _, t := range stuck {
		if n, ok := still[[2]uint32{t.PID, t.TID}]; ok && n.WaitTime == t.WaitTime && n.CtxSwitches == t.CtxSwitches {
			continue // still in the same wait: not the opener
		}
		pids[t.PID] = true
	}
	var out []uint32
	for p := range pids {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func selfIn(stuck []Thread, self uint32) bool {
	for _, t := range stuck {
		if self != 0 && t.PID == self {
			return true
		}
	}
	return false
}

// ---- watcher over all baits ----

// Watcher keeps a guard on every bait and reports openers while they're paused.
type Watcher struct {
	// OnOpen gets the program(s) that opened the bait, identified by waking up
	// exactly when ABA let go. It runs a few ms after the open.
	// intent is what the open asked for (see Intent).
	OnOpen func(path string, at time.Time, intent Intent, pids []uint32)
	// OnGhost gets the program(s) that opened the bait without letting Windows
	// pause them (see the package comment): found by who holds the file, not by
	// who woke. When ahead is true it runs before ABA lets go, so they haven't
	// read through that handle yet.
	OnGhost func(path string, at time.Time, intent Intent, pids []uint32, ahead bool)
	// OnOther runs for opens that neither read the contents nor change or
	// delete the file (security checks, attributes).
	OnOther func(path string, access uint32)
	// OnBlocked runs when a bait can't be guarded because some program keeps it
	// open (pids), which switches instant freeze off for that file.
	OnBlocked func(path string, pids []uint32)
	// Suspect (optional) picks, among programs paused inside an open, one
	// already known to be a suspect (sweeping, or a browser created suspended):
	// it's reported before the open is let go.
	Suspect func(path string, pids []uint32) uint32
	Logf    func(format string, args ...any)
	Self    uint32
	Settle  time.Duration

	mu     sync.Mutex
	active map[string]windows.Handle // path -> stop event
	armed  map[string]bool           // paths whose oplock is held right now
	wg     sync.WaitGroup
}

// Sync guards exactly the given paths (arming new ones, releasing removed ones).
func (w *Watcher) Sync(paths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active == nil {
		w.active = map[string]windows.Handle{}
	}
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
		if _, ok := w.active[p]; !ok {
			stop, err := windows.CreateEvent(nil, 1, 0, nil)
			if err != nil {
				continue
			}
			w.active[p] = stop
			w.wg.Add(1)
			go w.guard(p, stop)
		}
	}
	for p, stop := range w.active {
		if !want[p] {
			windows.SetEvent(stop)
			delete(w.active, p)
		}
	}
}

// Release lets go of the given paths right away (e.g. before deleting them).
func (w *Watcher) Release(paths []string) {
	w.mu.Lock()
	for _, p := range paths {
		if stop, ok := w.active[p]; ok {
			windows.SetEvent(stop)
			delete(w.active, p)
		}
	}
	w.mu.Unlock()
}

// Stop releases every guard and waits for them to finish.
func (w *Watcher) Stop() {
	w.Sync(nil)
	w.wg.Wait()
}

// Count of paths that should be guarded.
func (w *Watcher) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.active)
}

// Armed is how many of them are actually held right now. (A guard is briefly
// down after each open; one that stays down means something keeps the file
// open, see OnBlocked.)
func (w *Watcher) Armed() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for p := range w.active {
		if w.armed[p] {
			n++
		}
	}
	return n
}

func (w *Watcher) setArmed(path string, on bool) {
	w.mu.Lock()
	if w.armed == nil {
		w.armed = map[string]bool{}
	}
	if on {
		w.armed[path] = true
	} else {
		delete(w.armed, path)
	}
	w.mu.Unlock()
}

// Holders lists the programs that have path open, without disturbing them
// (the open asks only for attributes, which breaks no oplock and reads nothing).
func Holders(path string) []uint32 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	return (&Guard{h: h}).Users()
}

// blockedAfter is how many seconds a bait must stay un-guardable before OnBlocked.
var blockedAfter = 10

func (w *Watcher) logf(f string, a ...any) {
	if w.Logf != nil {
		w.Logf(f, a...)
	}
}

func (w *Watcher) guard(path string, stop windows.Handle) {
	defer w.wg.Done()
	defer windows.CloseHandle(stop)
	settle := w.Settle
	if settle == 0 {
		settle = 60 * time.Millisecond
	}
	stopped := func(d time.Duration) bool {
		r, _ := windows.WaitForSingleObject(stop, uint32(d.Milliseconds()))
		return r == windows.WAIT_OBJECT_0
	}
	fails := 0
	var busySince time.Time
	reported := false
	for {
		g, err := Arm(path)
		if err != nil {
			if fails++; fails == 1 {
				busySince, reported = time.Now(), false
			}
			// Busy or missing: retry quietly. But a bait that stays busy is one
			// some program is holding open, which keeps the guard off it.
			if !reported && time.Since(busySince) >= time.Duration(blockedAfter)*time.Second && errors.Is(err, ErrNotGranted) && w.OnBlocked != nil {
				reported = true
				var pids []uint32
				for _, p := range Holders(path) {
					if p != w.Self {
						pids = append(pids, p)
					}
				}
				if len(pids) > 0 {
					w.logf("instant: %s can't be guarded: held open by %v", path, pids)
					w.OnBlocked(path, pids)
				}
			}
			// Whoever has it open usually lets go within moments (a reader that
			// was just let through, or just killed), and until the guard is back
			// an open of this bait isn't paused: look again quickly at first.
			wait := time.Second
			if time.Since(busySince) < 5*time.Second {
				wait = 100 * time.Millisecond
			}
			if stopped(wait) {
				return
			}
			continue
		}
		fails = 0
		w.setArmed(path, true)
		r, _ := windows.WaitForMultipleObjects([]windows.Handle{g.Event(), stop}, false, windows.INFINITE)
		w.setArmed(path, false)
		if r != windows.WAIT_OBJECT_0 {
			g.Release()
			return
		}
		tick0, at := Tick(), time.Now()
		// Only opens that can read the contents, change them or delete the
		// file count. Windows reports the requested access for some opens
		// (e.g. delete) but not for plain reads, so "unknown" is treated as a
		// possible read.
		access, known := g.OpenerAccess()
		intent := intentOf(access, known)
		if known && !WantsContents(access) && !WantsChange(access) {

			if w.OnOther != nil {
				w.OnOther(path, access)
			}
			g.Release()
			if stopped(150 * time.Millisecond) {
				return
			}
			continue
		}
		// Whoever holds the bait open at this instant, and didn't before: only a
		// program that asked not to be paused has a handle already. (Asking
		// Windows takes tens of ms, so it runs alongside the wait below.)
		hc := make(chan []uint32, 1)
		go func() { hc <- g.NewUsers(w.Self) }()
		// ABA's own threads are included on purpose: when ABA itself reads a
		// bait (health check, repair), its stuck thread is the opener. Leaving it
		// out made any program that happened to wake at that instant look like
		// the opener, and get frozen for a read it never made.
		stuck := FindStuck(tick0, 0, settle)
		holders := <-hc
		own := selfIn(stuck, w.Self)
		// A ghost open is certain when nobody is paused at all, or when the one
		// program holding the bait is itself stuck (in its read: the open already
		// returned). Reported before letting go, so it hasn't read yet.
		if !own && len(holders) > 0 && (len(stuck) == 0 || (len(holders) == 1 && hasPID(stuckPIDs(stuck), holders[0]))) {
			w.logf("instant: %s opened by %v without being paused (ghost open)", path, holders)
			w.ghost(path, at, intent, holders, true)
			g.Release()
			if stopped(150 * time.Millisecond) {
				return
			}
			continue
		}
		// A program already known to be a suspect (sweeping other apps' data, a
		// browser created suspended going through a fake profile) is decided
		// while the open is still paused, so it never gets this file.
		if w.Suspect != nil && !own {
			if p := w.Suspect(path, stuckPIDs(stuck)); p != 0 {
				w.logf("instant: %s opened while pid %d (a known suspect) was paused in it", path, p)
				w.report(path, at, intent, []uint32{p})
				g.Release()
				if stopped(150 * time.Millisecond) {
					return
				}
				continue
			}
		}
		g.Release()
		pids := Woke(stuck, 0, 3*time.Millisecond)
		switch {
		case own:
			pids = nil // our own read
		case len(pids) > 1:
			// More than one program woke at that instant: don't guess. The
			// event-log path still catches whichever one actually reads.
			w.logf("instant: %s opened, but %v all woke at once; leaving it to the event log", path, pids)
			pids = nil
		case len(pids) == 1 && !hasPID(holders, pids[0]):
			w.logf("instant: %s opened by pid %d", path, pids[0])
		case len(holders) > 0:
			// Either the program that woke already held the bait (its open had
			// returned; it was waiting in a read), or threads were stuck but none
			// woke when ABA let go, so none was the opener: it's whoever holds the file.
			w.logf("instant: %s opened by %v without being paused (ghost open)", path, holders)
			w.ghost(path, at, intent, holders, false)
			pids = nil
		}
		w.report(path, at, intent, pids)
		// Give the opener time to finish before re-arming (a trusted reader may
		// still hold the file; Arm just retries until it's free).
		if stopped(150 * time.Millisecond) {
			return
		}
	}
}

func (w *Watcher) report(path string, at time.Time, intent Intent, pids []uint32) {
	if w.OnOpen == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			w.logf("instant freeze handler panicked: %v", p)
		}
	}()
	w.OnOpen(path, at, intent, pids)
}

func (w *Watcher) ghost(path string, at time.Time, intent Intent, pids []uint32, ahead bool) {
	if w.OnGhost == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			w.logf("instant freeze handler panicked: %v", p)
		}
	}()
	w.OnGhost(path, at, intent, pids, ahead)
}

func hasPID(pids []uint32, pid uint32) bool {
	for _, p := range pids {
		if p == pid {
			return true
		}
	}
	return false
}

func stuckPIDs(stuck []Thread) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, t := range stuck {
		if !seen[t.PID] {
			seen[t.PID] = true
			out = append(out, t.PID)
		}
	}
	return out
}

const outFlagModesProvided = 0x2

// OpenerAccess returns the access the opener asked for, when Windows says.
func (g *Guard) OpenerAccess() (uint32, bool) {
	if g.out.Flags&outFlagModesProvided == 0 {
		return 0, false
	}
	return g.out.AccessMode, true
}

// Intent is what an open of a bait asked for.
type Intent int

const (
	// Read: it can read the contents (or Windows didn't say what it asked
	// for, which is how plain reads arrive).
	Read Intent = iota
	// Write: it can change the contents and can't read them: an overwrite.
	Write
	// Delete: it can only delete or rename the file.
	Delete
)

func (i Intent) String() string { return [...]string{"read", "write", "delete"}[i] }

func intentOf(access uint32, known bool) Intent {
	switch {
	case !known || WantsContents(access):
		return Read
	case access&(fileWriteData|fileAppendData|genericWrite) != 0:
		return Write
	case access&accessDelete != 0:
		return Delete
	}
	return Read
}

const (
	fileWriteData  = 0x00000002
	fileAppendData = 0x00000004
	accessDelete   = 0x00010000
	genericWrite   = 0x40000000
)

// WantsChange reports whether an access mask can change the file's data or
// delete the file: what ransomware and wipers ask for. (Changing attributes
// or permissions doesn't count: backup and sync tools do that all day.)
func WantsChange(access uint32) bool {
	return access&(fileWriteData|fileAppendData|accessDelete|genericWrite) != 0
}

// WantsContents reports whether an access mask can read the file's data.
func WantsContents(access uint32) bool {
	const (
		fileReadData   = 0x00000001
		fileExecute    = 0x00000020
		maximumAllowed = 0x02000000
		genericAll     = 0x10000000
		genericExecute = 0x20000000
		genericRead    = 0x80000000
	)
	return access&(fileReadData|fileExecute|maximumAllowed|genericAll|genericExecute|genericRead) != 0
}
