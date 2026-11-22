package clipbait

// The clipboard side, on Windows.
//
// A Guard owns a hidden message-only window on its own thread. A cycle saves
// what's on the clipboard, puts a bait on it and watches for a few seconds;
// if a clipper swaps it, the cycle works out which program did (identify) and
// leaves that program paused, and Finish puts the person's clipboard back.
//
// Whatever the clipboard had is only ever saved when it can be put back
// exactly (plain text, and the formats browsers and editors put next to it);
// anything else (files, pictures, Office objects) means no bait this time.

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/session"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pOpenClipboard              = user32.NewProc("OpenClipboard")
	pCloseClipboard             = user32.NewProc("CloseClipboard")
	pEmptyClipboard             = user32.NewProc("EmptyClipboard")
	pSetClipboardData           = user32.NewProc("SetClipboardData")
	pGetClipboardData           = user32.NewProc("GetClipboardData")
	pGetClipboardOwner          = user32.NewProc("GetClipboardOwner")
	pGetOpenClipboardWindow     = user32.NewProc("GetOpenClipboardWindow")
	pGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
	pEnumClipboardFormats       = user32.NewProc("EnumClipboardFormats")
	pCountClipboardFormats      = user32.NewProc("CountClipboardFormats")
	pGetClipboardFormatNameW    = user32.NewProc("GetClipboardFormatNameW")
	pRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	pRegisterClassExW           = user32.NewProc("RegisterClassExW")
	pCreateWindowExW            = user32.NewProc("CreateWindowExW")
	pDestroyWindow              = user32.NewProc("DestroyWindow")
	pDefWindowProcW             = user32.NewProc("DefWindowProcW")
	pPeekMessageW               = user32.NewProc("PeekMessageW")
	pDispatchMessageW           = user32.NewProc("DispatchMessageW")
	pMsgWaitForMultipleObjects  = user32.NewProc("MsgWaitForMultipleObjects")
	pGetWindowThreadProcessId   = user32.NewProc("GetWindowThreadProcessId")
	pGetLastInputInfo           = user32.NewProc("GetLastInputInfo")
	pGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	pGlobalLock                 = kernel32.NewProc("GlobalLock")
	pGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	pGlobalSize                 = kernel32.NewProc("GlobalSize")
	pGlobalFree                 = kernel32.NewProc("GlobalFree")
	pGetTickCount               = kernel32.NewProc("GetTickCount")
)

const (
	cfText         = 1
	cfOEMText      = 7
	cfUnicodeText  = 13
	cfLocale       = 16
	gmemMoveable   = 0x2
	wmDestroyClip  = 0x0307
	pmRemove       = 1
	qsAllInput     = 0x04FF
	hwndMessage    = ^uintptr(2) // HWND_MESSAGE, (HWND)-3
	maxSavedBytes  = 8 << 20
	defaultWindow  = 2500 * time.Millisecond
	defaultConfirm = 1500 * time.Millisecond
)

// Formats that are only there to go with text: browsers, editors and
// clipboard tools add them. With anything else on the clipboard, no bait.
var textFormats = map[string]bool{
	"HTML Format": true, "Rich Text Format": true, "Rich Text Format Without Objects": true, "RTF As Text": true,
	"text/html": true, "text/plain": true, "text/_moz_htmlcontext": true, "text/_moz_htmlinfo": true,
	"text/x-moz-url-priv": true, "application/x-moz-nativehtml": true,
	"Chromium internal source URL": true, "Chromium internal source RFH token": true,
	"Chromium Web Custom MIME Data Format": true, "msSourceUrl": true,
	"UniformResourceLocator": true, "UniformResourceLocatorW": true,
	"vscode-editor-data": true, "MSDEVColumnSelect": true, "MSDEVLineSelect": true,
	"VisualStudioEditorOperationsLineCutCopyClipboardTag": true,
	"Clipboard Viewer Ignore":                             true,
	flagNoMonitor:                                         true, flagNoHistory: true, flagNoCloud: true,
}

// OLE's bookkeeping, next to what a program copied through it (the new
// Notepad does): left out, and what it describes put back as plain formats.
var oleFormats = map[string]bool{"DataObject": true, "Ole Private Data": true}

// What keeps a bait (and the copy put back afterwards) out of Win+V history,
// off other devices, and out of well-behaved clipboard managers.
const (
	flagNoMonitor = "ExcludeClipboardContentFromMonitorProcessing"
	flagNoHistory = "CanIncludeInClipboardHistory"
	flagNoCloud   = "CanUploadToCloudClipboard"
)

// Skipped is why a cycle put no bait out. It's not a failure: the clipboard
// held something that can't be put back exactly, or someone was using the PC.
type Skipped string

func (s Skipped) Error() string { return "no bait this time: " + string(s) }

// TestResult is how a bait put out on request (`aba clipboard test`) went,
// when no clipper was caught.
type TestResult struct {
	Time time.Time `json:"time"`
	// Result: "skipped" (no bait went out, see Skipped), "untouched" (nothing
	// swapped it), "unproven" (swapped, by a program that couldn't be pinned
	// down) or "error".
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}

// Finding is a clipper caught swapping a bait.
type Finding struct {
	Time        time.Time     `json:"time"`
	Coin        Coin          `json:"coin"`
	Bait        string        `json:"bait"`        // the fake address put on the clipboard
	Replacement string        `json:"replacement"` // what it was swapped for: the attacker's address
	Latency     time.Duration `json:"latency"`     // how quickly
	// PID is the clipper, proven by pausing it: while paused, a fresh bait
	// stayed put; let go, it swapped that one too. 0 if no program could be
	// pinned down; Suspects then lists any that Windows named.
	PID      uint32   `json:"pid,omitempty"`
	How      string   `json:"how,omitempty"` // how it was found, for the alert
	Suspects []uint32 `json:"suspects,omitempty"`
	// Held: the clipper is still paused, by the Guard, until Finish.
	Held bool `json:"held,omitempty"`
	// Interrupted: someone started using the PC midway, so the search stopped.
	Interrupted bool `json:"interrupted,omitempty"`
	// Keyed: the bait was a real address whose key ABA holds (not a lookalike).
	Keyed bool `json:"keyed,omitempty"`
}

// Guard puts baits on the clipboard of the session it runs in. Its methods
// may be called from any goroutine; the clipboard work happens on the
// Guard's own thread.
type Guard struct {
	// Candidates lists processes that might be the clipper, for when Windows
	// can't say (a clipper with no window). Each is only looked at if it has
	// the bait in its memory. Nil: only what Windows names is tried.
	Candidates func() []uint32
	// LastInput is when the person last typed, clicked or moved the mouse,
	// as a tick count; any change stops a bait at once. Nil: GetLastInputInfo.
	LastInput func() uint32
	Logf      func(format string, a ...any)
	// Window is how long a bait waits for a swap; Confirm how long each step
	// of proving a program is the clipper waits.
	Window, Confirm time.Duration
	// NewBait makes the address for each bait: Keys.Bait, for real addresses
	// whose keys ABA holds. Nil: lookalikes (invalid addresses; see Lookalike).
	NewBait func(Coin) string
	// AsUser starts this program with args as the person logged on to the
	// session, to save and put back their clipboard (`aba clipboard-keeper`,
	// see RunKeeper). As SYSTEM, the Guard can read the plain text of what
	// most programs copy but not the rest (a browser's HTML, say), and won't
	// put out a bait over what it couldn't put back. Nil, or when it fails:
	// the Guard does it itself.
	AsUser func(args ...string) (*session.Helper, error)

	onThread func() error // tests: put the thread on a private desktop

	jobs  chan func()
	wake  windows.Handle
	done  chan struct{}
	hwnd  uintptr
	self  uint32
	saved []clipFormat // the person's clipboard, kept until Finish
	have  bool         // saved holds something to put back
	baits []string     // baits out this cycle
	held  uint32       // the clipper, paused until Finish
	input uint32       // LastInput when the cycle began
	coin  int          // next coin to try in a pause test

	// set by the window procedure
	destroyedBy uint32
}

type clipFormat struct {
	id   uint32
	name string // a registered format's name ("" for Windows' own)
	data []byte
}

// one Guard per process: the window procedure needs to find it.
var current *Guard

// Start starts g's thread and window.
func (g *Guard) Start() error {
	if current != nil {
		return errors.New("clipbait: a guard is already running in this process")
	}
	if g.Window == 0 {
		g.Window = defaultWindow
	}
	if g.Confirm == 0 {
		g.Confirm = defaultConfirm
	}
	if g.Logf == nil {
		g.Logf = func(string, ...any) {}
	}
	if g.LastInput == nil {
		g.LastInput = lastInput
	}
	g.self = uint32(os.Getpid())
	g.jobs = make(chan func())
	g.done = make(chan struct{})
	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	g.wake = ev
	started := make(chan error, 1)
	go g.loop(started)
	if err := <-started; err != nil {
		windows.CloseHandle(ev)
		return err
	}
	current = g
	return nil
}

// Stop puts the clipboard back if a cycle left it baited, lets go of a held
// clipper, and ends the thread.
func (g *Guard) Stop() {
	if g.jobs == nil {
		return
	}
	g.Finish()
	close(g.done)
	windows.SetEvent(g.wake)
	current = nil
}

// loop is the Guard's thread. It keeps handling the window's messages even
// between cycles: once the Guard has put the clipboard back it owns it, and
// whoever copies something next waits for its window to answer.
func (g *Guard) loop(started chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if g.onThread != nil {
		if err := g.onThread(); err != nil {
			started <- err
			return
		}
	}
	g.hwnd = makeWindow()
	if g.hwnd == 0 {
		started <- errors.New("clipbait: could not create the guard's window")
		return
	}
	defer pDestroyWindow.Call(g.hwnd)
	started <- nil
	for {
		pMsgWaitForMultipleObjects.Call(1, uintptr(unsafe.Pointer(&g.wake)), 0, 1000, qsAllInput)
		pump()
		select {
		case <-g.done:
			return
		case job := <-g.jobs:
			job()
		default:
		}
	}
}

// do runs fn on the Guard's thread and waits for it.
func (g *Guard) do(fn func()) {
	finished := make(chan struct{})
	go func() {
		select {
		case g.jobs <- func() { fn(); close(finished) }:
		case <-g.done:
			close(finished)
		}
	}()
	windows.SetEvent(g.wake)
	for {
		select {
		case <-finished:
			return
		case <-time.After(50 * time.Millisecond):
			windows.SetEvent(g.wake) // in case the thread was busy when first woken
		}
	}
}

// Cycle puts one bait of coin out and watches it. It returns nil, nil when
// nothing swapped it, a Skipped error when no bait went out, and a Finding
// when a clipper swapped it. After a Finding, call Finish once the clipper
// has been dealt with: it stays paused, and the bait on the clipboard, until then.
func (g *Guard) Cycle(c Coin) (f *Finding, err error) {
	g.do(func() { f, err = g.cycle(c) })
	return f, err
}

// Finish lets go of a clipper the last cycle left paused (pause it yourself
// first to keep it frozen) and puts the person's clipboard back.
func (g *Guard) Finish() { g.do(g.finish) }

func (g *Guard) cycle(c Coin) (*Finding, error) {
	g.finish()
	g.input = g.LastInput()
	saved, start, err := g.snapshot()
	if err != nil {
		return nil, err
	}
	g.saved, g.have = saved, true
	bait := g.newBait(c)
	at, err := g.setBait(bait, start)
	if err != nil {
		g.have = false
		return nil, err
	}
	o := g.watch(bait, at, g.Window)
	switch {
	case o.interrupted:
		g.finish()
		return nil, Skipped("someone started using the PC")
	case !o.swapped:
		g.finish()
		return nil, nil
	case o.text != "" && !Looks(o.text):
		// Something copied that isn't an address (the person, a remote desktop
		// passing on a copy from the other side): theirs now, leave it.
		g.have, g.baits = false, nil
		return nil, Skipped("something else was copied")
	}
	f := &Finding{Time: time.Now(), Coin: c, Bait: bait, Replacement: o.text, Latency: o.latency, Keyed: g.NewBait != nil}
	g.identify(f, o)
	if f.Replacement == "" && f.PID == 0 {
		// Wiped, but by nothing that could be pinned down: that alone isn't
		// proof of a clipper (a tool that clears the clipboard could do it).
		g.Logf("clipboard bait: the bait was wiped right after it went out, by a program that couldn't be pinned down")
		g.finish()
		return nil, nil
	}
	return f, nil
}

func (g *Guard) newBait(c Coin) string {
	if g.NewBait != nil {
		if b := g.NewBait(c); b != "" {
			return b
		}
	}
	return Lookalike(c)
}

func (g *Guard) finish() {
	if g.held != 0 {
		procinfo.Resume(g.held)
		g.held = 0
	}
	if g.have {
		g.restore()
	}
	g.have, g.saved, g.baits = false, nil, nil
}

// snapshot copies what's on the clipboard, if it can all be put back exactly.
// It returns the clipboard's sequence number at the time.
func (g *Guard) snapshot() ([]clipFormat, uint32, error) {
	if g.AsUser != nil {
		saved, at, err := g.keeperSave()
		var skipped Skipped
		if err == nil || errors.As(err, &skipped) {
			return saved, at, err
		}
		g.Logf("clipboard bait: saving the clipboard as the person: %v (trying as SYSTEM)", err)
	}
	return readClipboard(g.hwnd)
}

// readClipboard copies what's on the clipboard, opened with hwnd, if it can
// all be put back exactly. It returns the clipboard's sequence number then.
func readClipboard(hwnd uintptr) ([]clipFormat, uint32, error) {
	if !openClip(hwnd) {
		return nil, 0, Skipped("another program has the clipboard open")
	}
	defer closeClip()
	at := seq()
	var out []clipFormat
	total := 0
	for f := enumFormats(0); f != 0; f = enumFormats(f) {
		reg := formatName(f)
		if oleFormats[reg] {
			continue // OLE's own bookkeeping: see oleFormats
		}
		name := reg
		if name == "" {
			name = fmt.Sprintf("format %d", f)
		}
		if f != cfText && f != cfOEMText && f != cfUnicodeText && f != cfLocale && !textFormats[name] {
			return nil, 0, Skipped("the clipboard holds more than text (" + name + ")")
		}
		data, ok := readFormat(f)
		if !ok && (f == cfText || f == cfOEMText || f == cfLocale) {
			continue // Windows makes these from the text again when it's put back
		}
		if !ok {
			// Typically: the program that copied it hasn't handed it over yet
			// (it gives it when asked, and isn't answering).
			return nil, 0, Skipped("part of the clipboard couldn't be read (" + name + ")")
		}
		if total += len(data); total > maxSavedBytes {
			return nil, 0, Skipped("what's on the clipboard is very large")
		}
		out = append(out, clipFormat{f, reg, data})
	}
	return out, at, nil
}

// restore puts the saved clipboard back, unless something new was copied in
// the meantime: then that stays.
func (g *Guard) restore() {
	if g.AsUser != nil {
		err := g.keeperRestore()
		if err == nil {
			return
		}
		g.Logf("clipboard bait: putting the clipboard back as the person: %v (trying as SYSTEM)", err)
	}
	if !writeClipboard(g.hwnd, g.saved, g.isBait) {
		g.Logf("clipboard bait: couldn't open the clipboard to put it back")
	}
}

// writeClipboard puts saved back on the clipboard, opened with hwnd, unless
// something new was copied in the meantime (isBait tells a bait from that).
// It reports false if the clipboard couldn't be opened.
func writeClipboard(hwnd uintptr, saved []clipFormat, isBait func(string) bool) bool {
	if !openClip(hwnd) {
		return false
	}
	defer closeClip()
	now := readText()
	wiped := now == "" && countFormats() == 0
	if !isBait(now) && !Looks(now) && !wiped {
		return true // not ours, nor a clipper's swap: someone copied something since
	}
	pEmptyClipboard.Call()
	flags := map[uint32]bool{}
	for _, f := range saved {
		id := f.id
		if f.name != "" {
			id = registerFormat(f.name) // the same number everywhere, but don't count on it
		}
		if id != 0 {
			setFormat(id, f.data)
			flags[id] = true
		}
	}
	if len(saved) > 0 {
		// It's already in Win+V history and synced: don't add it again.
		for _, name := range []string{flagNoMonitor, flagNoHistory, flagNoCloud} {
			if id := registerFormat(name); id != 0 && !flags[id] {
				setFormat(id, make([]byte, 4))
			}
		}
	}
	return true
}

func (g *Guard) isBait(s string) bool {
	for _, b := range g.baits {
		if s == b {
			return true
		}
	}
	return false
}

// setBait puts text on the clipboard as a bait. ifAt, if not 0, is the
// sequence number the clipboard must still have (nothing copied since).
func (g *Guard) setBait(text string, ifAt uint32) (uint32, error) {
	if !openClip(g.hwnd) {
		return 0, Skipped("another program has the clipboard open")
	}
	defer closeClip()
	if ifAt != 0 && seq() != ifAt {
		return 0, Skipped("something was just copied")
	}
	pEmptyClipboard.Call()
	u, _ := windows.UTF16FromString(text)
	if !setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)) {
		return 0, errors.New("clipbait: could not put the bait on the clipboard")
	}
	for _, name := range []string{flagNoMonitor, flagNoHistory, flagNoCloud} {
		if id := registerFormat(name); id != 0 {
			setFormat(id, make([]byte, 4))
		}
	}
	g.baits = append(g.baits, text)
	g.destroyedBy = 0
	return seq(), nil
}

type observation struct {
	swapped, interrupted bool
	text                 string
	latency              time.Duration
	// Who Windows says did it: the clipboard's owner the moment it changed
	// and once it could be read, and which window had it open when it wiped
	// the bait (we owned the bait, so Windows told us, mid-wipe).
	ownerFirst, ownerAfter, wipedBy uint32
}

// watch waits up to timeout for the clipboard to change from bait. A bait
// wiped and left empty counts as a change (text ""): a clipper that opens the
// clipboard with no window gets its address refused by Windows after it has
// wiped the clipboard, so that's all a swap by one of those may leave.
func (g *Guard) watch(bait string, start uint32, timeout time.Duration) observation {
	const settle = 50 * time.Millisecond // an empty clipboard may be about to be filled
	t0 := time.Now()
	var emptySince time.Time
	var first uint32 // owner when the change was first seen
	for time.Since(t0) < timeout {
		pump()
		if g.LastInput() != g.input {
			return observation{interrupted: true}
		}
		if seq() == start {
			time.Sleep(time.Millisecond)
			continue
		}
		h, _, _ := pGetClipboardOwner.Call()
		if first == 0 {
			first = hwndPid(h)
		}
		if !openClip(g.hwnd) {
			continue // still busy: look again
		}
		text, empty := readText(), countFormats() == 0
		closeClip()
		if text == "" && !empty {
			// Something without text: someone copied a picture or files over it.
			return observation{swapped: true, text: "(not text)", latency: time.Since(t0)}
		}
		if text == "" {
			if emptySince.IsZero() {
				emptySince = time.Now()
			}
			if time.Since(emptySince) < settle {
				time.Sleep(2 * time.Millisecond)
				continue
			}
		}
		pump()
		o := observation{text: text, latency: time.Since(t0), ownerFirst: first, wipedBy: g.destroyedBy}
		h, _, _ = pGetClipboardOwner.Call()
		o.ownerAfter = hwndPid(h)
		if text != bait {
			o.swapped = true
			return o
		}
		start, first, emptySince = seq(), 0, time.Time{}
	}
	return observation{}
}

// identify works out which program swapped the bait, and proves it: paused,
// it must leave a fresh bait alone; let go, it must swap that one too. The
// programs Windows names (the clipboard's owner, whoever had it open while
// wiping the bait) are tried first. A clipper with no window of its own leaves
// no name, so then each candidate with the bait in its memory is tried.
func (g *Guard) identify(f *Finding, o observation) {
	tried := map[uint32]bool{0: true, g.self: true}
	try := func(pid uint32, how string) bool {
		if tried[pid] {
			return false
		}
		tried[pid] = true
		ok, interrupted := g.pauseTest(pid)
		if interrupted {
			f.Interrupted = true
			return true
		}
		if ok {
			f.PID, f.How, f.Held = pid, how, true
		}
		return ok
	}
	named := []struct {
		pid uint32
		how string
	}{
		{o.ownerFirst, "it took over the clipboard to swap the address"},
		{o.wipedBy, "it had the clipboard open while it wiped the address"},
		{o.ownerAfter, "it took over the clipboard to swap the address"},
	}
	for _, n := range named {
		if n.pid != 0 && n.pid != g.self {
			f.Suspects = appendPID(f.Suspects, n.pid)
		}
	}
	for _, n := range named {
		if try(n.pid, n.how) {
			return
		}
	}
	if g.Candidates == nil {
		return
	}
	for _, pid := range g.Candidates() {
		if tried[pid] {
			continue
		}
		if !holds(pid, f.Bait, f.Replacement) {
			continue
		}
		if try(pid, "it had the address in its memory, and the swapping stopped while it was paused") {
			return
		}
		if f.Interrupted {
			return
		}
	}
}

func appendPID(xs []uint32, p uint32) []uint32 {
	for _, x := range xs {
		if x == p {
			return xs
		}
	}
	return append(xs, p)
}

// inputNote says when the mouse or keyboard was last used, for the log when
// that stopped a cycle.
func (g *Guard) inputNote() string {
	now, _, _ := pGetTickCount.Call()
	last := g.LastInput()
	return fmt.Sprintf("the mouse or keyboard was used %d ms ago (%d ms after this bait began)",
		uint32(now)-last, last-g.input)
}

// pauseTest proves pid is the clipper: paused, it leaves a fresh bait alone;
// let go, it swaps it. Proven, it's paused again and held until Finish.
//
// Two things must never happen to a paused program, or copying and pasting
// stops working for everyone until it's let go: it must not own the clipboard
// (whoever empties it next waits for the owner's window to answer, and a
// paused one never does), and it must not be paused with the clipboard open.
// So the Guard opens the clipboard and takes it over first, and pauses the
// program while it has the clipboard open itself (see takeOver).
func (g *Guard) pauseTest(pid uint32) (proven, interrupted bool) {
	bait := g.newBait(Coins[g.coin%len(Coins)])
	g.coin++
	at, ok := g.takeOver(bait, pid)
	if !ok {
		return false, false
	}
	g.baits = append(g.baits, bait)
	o := g.watch(bait, at, g.Confirm)
	procinfo.Resume(pid)
	if o.interrupted {
		g.Logf("clipboard bait: stopped proving pid %d (while paused): %s", pid, g.inputNote())
		return false, true
	}
	if o.swapped {
		g.Logf("clipboard bait: pid %d paused, yet the bait was swapped", pid)
		return false, false // something else did it
	}
	o = g.watch(bait, at, g.Confirm)
	if o.interrupted {
		g.Logf("clipboard bait: stopped proving pid %d (let go): %s", pid, g.inputNote())
		return false, true
	}
	if !o.swapped || !(Looks(o.text) || o.text == "") {
		g.Logf("clipboard bait: pid %d let go, and the bait wasn't swapped", pid)
		return false, false
	}
	if _, ok := g.takeOver(o.text, pid); !ok {
		g.Logf("clipboard bait: pid %d is the clipper, but couldn't be paused again", pid)
		return false, false
	}
	g.held = pid
	return true, false
}

// takeOver makes the Guard the clipboard's owner with text on it and, while
// it still has the clipboard open, pauses pid. Holding the clipboard open is
// what guarantees pid doesn't have it open at the moment it's paused. (pid is
// still running while the clipboard is emptied, so if it was the owner, it
// answers.) It returns the clipboard's sequence number afterwards.
func (g *Guard) takeOver(text string, pid uint32) (uint32, bool) {
	if !openClip(g.hwnd) {
		g.Logf("clipboard bait: the clipboard stayed busy, so pid %d wasn't tested", pid)
		return 0, false
	}
	pEmptyClipboard.Call()
	u, _ := windows.UTF16FromString(text)
	setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2))
	for _, name := range []string{flagNoMonitor, flagNoHistory, flagNoCloud} {
		if id := registerFormat(name); id != 0 {
			setFormat(id, make([]byte, 4))
		}
	}
	err := procinfo.Suspend(pid)
	g.destroyedBy = 0
	closeClip()
	if err != nil {
		g.Logf("clipboard bait: couldn't pause pid %d: %v", pid, err)
		return 0, false
	}
	return seq(), true
}

// ---------- Windows clipboard plumbing ----------

func seq() uint32 { r, _, _ := pGetClipboardSequenceNumber.Call(); return uint32(r) }

func lastInput() uint32 {
	var lii struct{ size, time uint32 }
	lii.size = uint32(unsafe.Sizeof(lii))
	pGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	return lii.time
}

// openClip opens the clipboard, waiting a little if another program has it.
// It keeps answering the window's messages meanwhile: the program that has
// the clipboard open may be waiting for this window to answer one (it's
// emptying a clipboard this window owns).
func openClip(hwnd uintptr) bool {
	for i := 0; i < 100; i++ {
		if r, _, _ := pOpenClipboard.Call(hwnd); r != 0 {
			return true
		}
		pump()
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

func closeClip() { pCloseClipboard.Call() }

func enumFormats(after uint32) uint32 {
	r, _, _ := pEnumClipboardFormats.Call(uintptr(after))
	return uint32(r)
}

func formatName(f uint32) string {
	if f < 0xC000 {
		return ""
	}
	buf := make([]uint16, 256)
	n, _, _ := pGetClipboardFormatNameW.Call(uintptr(f), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:n])
}

func countFormats() int {
	r, _, _ := pCountClipboardFormats.Call()
	return int(r)
}

func registerFormat(name string) uint32 {
	p, _ := windows.UTF16PtrFromString(name)
	r, _, _ := pRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(p)))
	return uint32(r)
}

func readFormat(f uint32) ([]byte, bool) {
	h, _, _ := pGetClipboardData.Call(uintptr(f))
	if h == 0 {
		return nil, false
	}
	size, _, _ := pGlobalSize.Call(h)
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		return nil, false
	}
	defer pGlobalUnlock.Call(h)
	return append([]byte(nil), globalMem(p, int(size))...), true
}

// globalMem is the n bytes at p, memory GlobalLock handed out (not Go's,
// so the garbage collector never moves it).
func globalMem(p uintptr, n int) []byte {
	return unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&p))), n)
}

func readText() string {
	data, ok := readFormat(cfUnicodeText)
	if !ok || len(data) < 2 {
		return ""
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&data[0])), len(data)/2)
	return windows.UTF16ToString(u)
}

// setFormat puts a copy of data on the open clipboard as format f.
func setFormat(f uint32, data []byte) bool {
	n := len(data)
	if n == 0 {
		n = 1
	}
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, uintptr(n))
	if h == 0 {
		return false
	}
	p, _, _ := pGlobalLock.Call(h)
	if p == 0 {
		pGlobalFree.Call(h)
		return false
	}
	copy(globalMem(p, n), data)
	pGlobalUnlock.Call(h)
	if r, _, _ := pSetClipboardData.Call(uintptr(f), h); r == 0 {
		pGlobalFree.Call(h)
		return false
	}
	return true
}

func hwndPid(h uintptr) uint32 {
	if h == 0 {
		return 0
	}
	var pid uint32
	pGetWindowThreadProcessId.Call(h, uintptr(unsafe.Pointer(&pid)))
	return pid
}

func pump() {
	var m struct {
		hwnd    uintptr
		message uint32
		wparam  uintptr
		lparam  uintptr
		time    uint32
		x, y    int32
		private uint32
	}
	for {
		if r, _, _ := pPeekMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0, pmRemove); r == 0 {
			return
		}
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

var wndProc = windows.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
	if msg == wmDestroyClip {
		// Sent to us, the bait's owner, from inside the other program's
		// EmptyClipboard: it still has the clipboard open right now.
		if g := current; g != nil {
			w, _, _ := pGetOpenClipboardWindow.Call()
			g.destroyedBy = hwndPid(w)
		}
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(h, msg, wp, lp)
	return r
})

var classRegistered bool

func makeWindow() uintptr {
	name, _ := windows.UTF16PtrFromString("ABAClipboardBait")
	if !classRegistered {
		wc := struct {
			size, style            uint32
			proc                   uintptr
			clsExtra, wndExtra     int32
			instance, icon, cursor windows.Handle
			background             windows.Handle
			menu, class            *uint16
			iconSm                 windows.Handle
		}{proc: wndProc, class: name}
		wc.size = uint32(unsafe.Sizeof(wc))
		pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		classRegistered = true
	}
	h, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(name)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, 0, 0)
	return h
}
