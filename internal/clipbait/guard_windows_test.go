package clipbait

// These tests never touch the real clipboard. TestMain moves the test process
// into a private window station of its own (which has its own clipboard), and
// the fake clippers are harmless copies of this test binary started inside it:
// they only ever swap fake addresses for other fake addresses.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pCreateWindowStationW       = user32.NewProc("CreateWindowStationW")
	pSetProcessWindowStation    = user32.NewProc("SetProcessWindowStation")
	pCreateDesktopW             = user32.NewProc("CreateDesktopW")
	pSetThreadDesktop           = user32.NewProc("SetThreadDesktop")
	pGetUserObjectInformationW  = user32.NewProc("GetUserObjectInformationW")
	pAddClipboardFormatListener = user32.NewProc("AddClipboardFormatListener")
	pGetMessageW                = user32.NewProc("GetMessageW")
	pSuspendThread              = kernel32.NewProc("SuspendThread")
)

const fakeEnv = "ABA_CLIPBAIT_FAKE"

var (
	testDesk     uintptr // the private desktop, for the guard's thread
	testDeskPath string  // station\desktop, for children
	noStation    string  // why there's no private window station (tests skip)
)

func TestMain(m *testing.M) {
	if role := os.Getenv(fakeEnv); role != "" {
		fake(role)
		return
	}
	if len(os.Args) > 1 && systemSide(os.Args[1:]) { // see system_windows_test.go
		return
	}
	if err := privateStation(nil); err != nil {
		noStation = err.Error()
	}
	os.Exit(m.Run())
}

// privateStation moves this process onto a window station of its own. sa,
// if not nil, says who else may use it.
func privateStation(sa *windows.SecurityAttributes) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Unnamed: Windows names it. (Without admin rights, a name is refused.)
	ws, _, e := pCreateWindowStationW.Call(0, 0, 0x37F /* WINSTA_ALL_ACCESS */, uintptr(unsafe.Pointer(sa)))
	if ws == 0 {
		return fmt.Errorf("CreateWindowStation: %v", e)
	}
	buf := make([]uint16, 256)
	var need uint32
	pGetUserObjectInformationW.Call(ws, 2 /* UOI_NAME */, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&need)))
	if r, _, e := pSetProcessWindowStation.Call(ws); r == 0 {
		return fmt.Errorf("SetProcessWindowStation: %v", e)
	}
	name, _ := windows.UTF16PtrFromString("clipbait")
	d, _, e := pCreateDesktopW.Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, 0x10000000 /* GENERIC_ALL */, uintptr(unsafe.Pointer(sa)))
	if d == 0 {
		return fmt.Errorf("CreateDesktop: %v", e)
	}
	testDesk, testDeskPath = d, windows.UTF16ToString(buf)+`\clipbait`
	return nil
}

func newGuard(t *testing.T, g *Guard) *Guard {
	t.Helper()
	if noStation != "" {
		t.Skip("no private window station, so not touching any clipboard: " + noStation)
	}
	g.onThread = func() error {
		if r, _, e := pSetThreadDesktop.Call(testDesk); r == 0 {
			return fmt.Errorf("SetThreadDesktop: %v", e)
		}
		return nil
	}
	if g.LastInput == nil {
		g.LastInput = func() uint32 { return 1 } // nobody at the keyboard
	}
	// Generous: these run at low priority next to whatever else the PC is doing.
	if g.Window == 0 {
		g.Window = 6 * time.Second
	}
	if g.Confirm == 0 {
		g.Confirm = 3 * time.Second
	}
	g.Logf = t.Logf
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Stop)
	return g
}

// put sets the private clipboard to text (plus an HTML copy, like a browser).
func (g *Guard) put(t *testing.T, text string, extra ...string) {
	t.Helper()
	ok := false
	g.do(func() {
		if !openClip(g.hwnd) {
			return
		}
		defer closeClip()
		pEmptyClipboard.Call()
		u, _ := windows.UTF16FromString(text)
		ok = setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2))
		for _, name := range extra {
			ok = ok && setFormat(registerFormat(name), []byte("<b>"+text+"</b>"))
		}
	})
	if !ok {
		t.Fatal("couldn't set up the test clipboard")
	}
}

type clipState struct {
	text    string
	formats []string
}

func (g *Guard) get() clipState {
	var s clipState
	g.do(func() {
		if !openClip(g.hwnd) {
			return
		}
		defer closeClip()
		s.text = readText()
		for f := enumFormats(0); f != 0; f = enumFormats(f) {
			if n := formatName(f); n != "" {
				s.formats = append(s.formats, n)
			}
		}
	})
	return s
}

func (s clipState) has(format string) bool {
	for _, f := range s.formats {
		if f == format {
			return true
		}
	}
	return false
}

// ---------- the fake programs ----------

type child struct {
	role string
	pid  uint32
	h    windows.Handle
}

// start runs this test binary as one of the fake programs, inside the private
// window station, in a job that kills it when the test ends.
func start(t *testing.T, roles ...string) []child {
	t.Helper()
	logPath := fakeLogPath(t) // before the job: cleanups run last-first, so the children are gone before the log is removed
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	t.Cleanup(func() { windows.CloseHandle(job) })
	exe, _ := os.Executable()
	var out []child
	for _, role := range roles {
		env := append(os.Environ(), fakeEnv+"="+role, fakeEnv+"_LOG="+logPath)
		block, _ := envBlock(env)
		cl, _ := windows.UTF16PtrFromString(windows.EscapeArg(exe))
		si := &windows.StartupInfo{}
		si.Cb = uint32(unsafe.Sizeof(*si))
		si.Desktop, _ = windows.UTF16PtrFromString(testDeskPath)
		var pi windows.ProcessInformation
		flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED | windows.CREATE_UNICODE_ENVIRONMENT)
		if err := windows.CreateProcess(nil, cl, nil, nil, false, flags, &block[0], nil, si, &pi); err != nil {
			t.Fatal(err)
		}
		if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
			windows.TerminateProcess(pi.Process, 1)
			t.Fatal(err)
		}
		windows.ResumeThread(pi.Thread)
		windows.CloseHandle(pi.Thread)
		h := pi.Process
		t.Cleanup(func() { windows.CloseHandle(h) })
		out = append(out, child{role, pi.ProcessId, pi.Process})
	}
	time.Sleep(700 * time.Millisecond) // let them get going
	return out
}

var logPaths = map[*testing.T]string{}

// fakeLogPath is where the fake programs of test t write what they saw; it's
// printed if the test fails.
func fakeLogPath(t *testing.T) string {
	if p, ok := logPaths[t]; ok {
		return p
	}
	p := filepath.Join(t.TempDir(), "fakes.log")
	logPaths[t] = p
	t.Cleanup(func() {
		if t.Failed() {
			if b, err := os.ReadFile(p); err == nil {
				t.Logf("what the fake programs saw:\n%s", b)
			}
		}
	})
	return p
}

func envBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, kv := range env {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		b = append(b, u...)
	}
	return append(b, 0), nil
}

// fakeAttacker is what a fake clipper swaps an address of each coin for.
func fakeAttacker(role, text string) string {
	switch {
	case patterns[Bitcoin].MatchString(text):
		return Bait(Bitcoin)[:20] + strings.Repeat("z", 14)
	case patterns[BitcoinScript].MatchString(text):
		return Bait(BitcoinScript)[:20] + strings.Repeat("z", 14)
	case patterns[Tron].MatchString(text):
		return Bait(Tron)[:20] + strings.Repeat("z", 14)
	case patterns[Ethereum].MatchString(text):
		return "0x" + strings.Repeat("0", 38) + "ff"
	}
	return ""
}

// swapIn opens the clipboard (with hwnd, or with no window) and, if it holds
// an address, puts the fake attacker's in its place.
func swapIn(hwnd uintptr, role string) bool {
	if !openClip(hwnd) {
		flog("%s: couldn't open the clipboard", role)
		return false
	}
	defer closeClip()
	t := readText()
	if t == "" {
		h, _, e := pGetClipboardData.Call(cfUnicodeText)
		flog("%s: read nothing (handle %x, %v); will look again", role, h, e)
		return false
	}
	flog("%s: read %q", role, t)
	if strings.HasSuffix(t, "zzzzzzzzzzzzzz") || strings.HasSuffix(t, "00ff") {
		return true // ours already
	}
	a := fakeAttacker(role, t)
	if role == "copier" && t != "" && Looks(t) {
		a = "just some text someone copied"
	}
	if a == "" {
		return true
	}
	if r, _, e := pEmptyClipboard.Call(); r == 0 {
		flog("%s: EmptyClipboard failed: %v; will try again", role, e)
		return false
	}
	u, _ := windows.UTF16FromString(a)
	if !setFormat(cfUnicodeText, unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)) {
		flog("%s: SetClipboardData failed (left the clipboard empty)", role)
	}
	return true
}

var fakeLog *os.File

func flog(format string, a ...any) {
	if fakeLog != nil {
		fmt.Fprintf(fakeLog, time.Now().Format("15:04:05.000 ")+format+"\n", a...)
	}
}

func fake(role string) {
	runtime.LockOSThread()
	if p := os.Getenv(fakeEnv + "_LOG"); p != "" {
		fakeLog, _ = os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	}
	// poll calls fn when the clipboard changes, again and again until fn
	// manages to open it (real clippers retry too).
	poll := func(fn func() bool) {
		last := uint32(0) // look at once: the bait may be out before this starts
		for {
			// last becomes the number seen before fn ran, so a change made
			// while fn ran isn't missed (fn's own swap is seen and ignored).
			if s := seq(); s != last {
				ok := fn()
				flog("%s: seq %d -> %d, handled %v", role, last, s, ok)
				if ok {
					last = s
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	switch role {
	case "window": // the classic: a hidden window Windows notifies of every change
		h := makeWindow()
		pAddClipboardFormatListener.Call(h)
		var m [48]byte
		for {
			if r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m[0])), 0, 0, 0); int32(r) <= 0 {
				return
			}
			if *(*uint32)(unsafe.Pointer(&m[8])) == 0x031D { // WM_CLIPBOARDUPDATE
				for i := 0; i < 20 && !swapIn(h, role); i++ {
				}
			}
			pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m[0])))
		}
	case "nowindow": // crude: polls, and opens the clipboard with no window at all
		poll(func() bool { return swapIn(0, role) })
	case "hitrun": // evasive: a throwaway window only for the swap, gone right after
		poll(func() bool {
			if !openClip(0) {
				return false
			}
			t := readText()
			if t == "" {
				h, _, e := pGetClipboardData.Call(cfUnicodeText)
				flog("%s: read nothing at seq %d (%d formats, handle %x, %v)", role, seq(), countFormats(), h, e)
			}
			closeClip()
			if t == "" {
				return false
			}
			if a := fakeAttacker(role, t); a != "" && !strings.HasSuffix(t, "zzzzzzzzzzzzzz") && !strings.HasSuffix(t, "00ff") {
				h := makeWindow()
				defer pDestroyWindow.Call(h)
				return swapIn(h, role)
			}
			return true
		})
	case "copier": // not a clipper: copies some text over an address
		poll(func() bool { return swapIn(0, role) })
	case "reader": // innocent: reads every change, like a clipboard manager
		var history []string
		poll(func() bool {
			if !openClip(0) {
				return false
			}
			history = append(history, readText())
			closeClip()
			return true
		})
	}
	select {}
}

func pids(cs []child) func() []uint32 {
	return func() []uint32 {
		var out []uint32
		for _, c := range cs {
			out = append(out, c.pid)
		}
		return out
	}
}

// ---------- tests ----------

func TestNoClipperNothingFound(t *testing.T) {
	g := newGuard(t, &Guard{})
	cs := start(t, "reader")
	g.Candidates = pids(cs)
	g.put(t, "notes from yesterday", "HTML Format")
	f, err := g.Cycle(Bitcoin)
	if err != nil || f != nil {
		t.Fatalf("Cycle = %+v, %v; want nothing", f, err)
	}
	s := g.get()
	if s.text != "notes from yesterday" || !s.has("HTML Format") {
		t.Fatalf("clipboard not put back: %+v", s)
	}
	if !s.has(flagNoHistory) || !s.has(flagNoCloud) {
		t.Errorf("the copy put back should be kept out of clipboard history: %v", s.formats)
	}
}

func TestCatchesEachKindOfClipper(t *testing.T) {
	for _, kind := range []string{"window", "nowindow", "hitrun"} {
		t.Run(kind, func(t *testing.T) {
			g := newGuard(t, &Guard{})
			cs := start(t, "reader", kind)
			g.Candidates = pids(cs)
			clipper := cs[1]
			g.put(t, "a shopping list")
			for _, coin := range []Coin{Bitcoin, Ethereum} {
				f, err := g.Cycle(coin)
				if err != nil || f == nil {
					t.Fatalf("%s: Cycle = %+v, %v; want a finding", coin, f, err)
				}
				t.Logf("%s: %s -> %s in %v; pid %d (%s), suspects %v", coin, f.Bait, f.Replacement, f.Latency, f.PID, f.How, f.Suspects)
				if f.PID != clipper.pid || !f.Held {
					t.Fatalf("%s: blamed pid %d (held %v), want the %s clipper (pid %d); the reader is pid %d",
						coin, f.PID, f.Held, kind, clipper.pid, cs[0].pid)
				}
				if suspended(t, clipper.pid) != true {
					t.Fatalf("the clipper should be left paused until Finish")
				}
				g.Finish()
				if suspended(t, clipper.pid) {
					t.Fatal("Finish should let the clipper go")
				}
				if s := g.get(); s.text != "a shopping list" {
					t.Fatalf("clipboard not put back after the catch: %q", s.text)
				}
			}
		})
	}
}

// suspended reports whether every thread of pid is suspended.
func suspended(t *testing.T, pid uint32) bool {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	found, all := false, true
	for err := windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			continue
		}
		// Suspending and resuming at once reports the count it had.
		n, _, _ := pSuspendThread.Call(uintptr(th))
		windows.ResumeThread(th)
		windows.CloseHandle(th)
		found = true
		all = all && int32(n) > 0
	}
	return found && all
}

func TestLeavesSomethingElseAlone(t *testing.T) {
	g := newGuard(t, &Guard{})
	g.put(t, "a photo", "Some Private App Format")
	at := g.get()
	_, err := g.Cycle(Bitcoin)
	var skip Skipped
	if !errors.As(err, &skip) {
		t.Fatalf("Cycle = %v; want it skipped (the clipboard holds an app's own format)", err)
	}
	if s := g.get(); s.text != at.text || !s.has("Some Private App Format") {
		t.Fatalf("clipboard changed: %+v", s)
	}
}

func TestStopsWhenSomeoneIsBack(t *testing.T) {
	n := uint32(0)
	g := newGuard(t, &Guard{LastInput: func() uint32 { n++; return n / 50 }})
	g.put(t, "draft email")
	_, err := g.Cycle(Ethereum)
	var skip Skipped
	if !errors.As(err, &skip) {
		t.Fatalf("Cycle = %v; want it skipped", err)
	}
	if s := g.get(); s.text != "draft email" {
		t.Fatalf("clipboard not put back at once: %q", s.text)
	}
}

func TestSomethingCopiedIsNotAClipper(t *testing.T) {
	g := newGuard(t, &Guard{})
	cs := start(t, "copier")
	g.Candidates = pids(cs)
	g.put(t, "old text")
	f, err := g.Cycle(Tron)
	if f != nil {
		t.Fatalf("blamed pid %d for copying text over the bait", f.PID)
	}
	var skip Skipped
	if !errors.As(err, &skip) {
		t.Fatalf("Cycle = %v; want it skipped", err)
	}
	if s := g.get(); s.text != "just some text someone copied" {
		t.Fatalf("what was copied should stay, not be overwritten: %q", s.text)
	}
}

func TestBaitStaysOutOfHistory(t *testing.T) {
	g := newGuard(t, &Guard{})
	var s clipState
	g.do(func() {
		if _, err := g.setBait(Bait(Bitcoin), 0); err != nil {
			t.Error(err)
		}
	})
	s = g.get()
	for _, f := range []string{flagNoMonitor, flagNoHistory, flagNoCloud} {
		if !s.has(f) {
			t.Errorf("bait without %s", f)
		}
	}
	g.do(g.finish)
}
