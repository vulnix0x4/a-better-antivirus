package instant

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The test binary doubles as the "other program" for opens that cmd.exe can't
// make: ABA_TEST_OPEN=<how> <this binary> <path>.
func TestMain(m *testing.M) {
	if how := os.Getenv("ABA_TEST_OPEN"); how != "" {
		os.Exit(openHelper(how, os.Args[len(os.Args)-1]))
	}
	os.Exit(m.Run())
}

const (
	optCompleteIfOplocked = 0x100 // FILE_COMPLETE_IF_OPLOCKED: don't pause me
	optNonDirectory       = 0x40
	optSyncIO             = 0x20
	accReadData           = 0x1
	accExecute            = 0x20
	accReadAttributes     = 0x80
)

// ntOpen opens path the way CreateFile can't: with exact access and options.
func ntOpen(path string, access, options uint32) (windows.Handle, error) {
	us, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: us, Attributes: 0x40}
	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &iosb, nil, 0, 7, 1 /* FILE_OPEN */, options|optNonDirectory|optSyncIO, 0, 0)
	if h == 0 {
		return 0, err
	}
	return h, nil // "oplock break in progress" is a success: the handle is open
}

func openHelper(how, path string) int {
	var h windows.Handle
	var err error
	switch how {
	case "ghost-read": // refuse to be paused, then read
		if h, err = ntOpen(path, accReadData, optCompleteIfOplocked); err == nil {
			buf := make([]byte, 64)
			var n uint32
			windows.ReadFile(h, buf, &n, nil)
			os.WriteFile(path+".got", buf[:n], 0o644)
		}
	case "ghost-map": // refuse to be paused, never ask for read access, map it
		if h, err = ntOpen(path, accExecute, optCompleteIfOplocked); err == nil {
			if b := mapExecuteOnly(h, 8); b != nil {
				os.WriteFile(path+".got", b, 0o644)
			}
		}
	case "hold-attrs": // keep an attribute-only handle (breaks nothing)
		h, err = ntOpen(path, accReadAttributes, 0)
	case "hold-read": // keep the file open for reading
		h, err = ntOpen(path, accReadData, 0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, how, err)
		return 1
	}
	os.WriteFile(path+".ready", nil, 0o644)
	time.Sleep(20 * time.Second)
	return 0
}

// mapExecuteOnly reads the first n bytes of a file opened for execute only,
// through a memory mapping: content without ever holding read access.
func mapExecuteOnly(h windows.Handle, n int) []byte {
	nt := windows.NewLazySystemDLL("ntdll.dll")
	var sec windows.Handle
	if r, _, _ := nt.NewProc("NtCreateSection").Call(uintptr(unsafe.Pointer(&sec)), 0x8|0x1, 0, 0, windows.PAGE_EXECUTE, 0x8000000 /* SEC_COMMIT */, uintptr(h)); r != 0 {
		return nil
	}
	defer windows.CloseHandle(sec)
	var base unsafe.Pointer // filled in by the kernel
	var size uintptr
	if r, _, _ := nt.NewProc("NtMapViewOfSection").Call(uintptr(sec), ^uintptr(0), uintptr(unsafe.Pointer(&base)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 2, 0, windows.PAGE_EXECUTE); r != 0 {
		return nil
	}
	defer nt.NewProc("NtUnmapViewOfSection").Call(^uintptr(0), uintptr(base))
	return append([]byte(nil), unsafe.Slice((*byte)(base), n)...)
}

func helper(t *testing.T, how, path string) *exec.Cmd {
	t.Helper()
	c := exec.Command(os.Args[0], path)
	c.Env = append(os.Environ(), "ABA_TEST_OPEN="+how)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	return c
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
}

type opened struct {
	pids  []uint32
	ghost bool
	ahead bool
	got   bool // the opener already had the content when it was reported
}

func watch(t *testing.T, bait string) (*Watcher, chan opened) {
	t.Helper()
	ch := make(chan opened, 8)
	had := func() bool { b, _ := os.ReadFile(bait + ".got"); return len(b) > 0 }
	w := &Watcher{Self: uint32(os.Getpid()),
		OnOpen: func(_ string, _ time.Time, pids []uint32) { ch <- opened{pids: pids, got: had()} },
		OnGhost: func(_ string, _ time.Time, pids []uint32, ahead bool) {
			ch <- opened{pids: pids, ghost: true, ahead: ahead, got: had()}
		}}
	w.Sync([]string{bait})
	t.Cleanup(w.Stop)
	time.Sleep(150 * time.Millisecond)
	return w, ch
}

func newBait(t *testing.T) string {
	bait := filepath.Join(t.TempDir(), "passwords.txt")
	os.WriteFile(bait, []byte("email / hunter2\r\n"), 0o644)
	return bait
}

// A program that asks Windows not to pause it in the open never has a stuck
// thread. It's found by the handle it holds instead, before it can read.
func TestGhostOpenIsAttributed(t *testing.T) {
	bait := newBait(t)
	_, ch := watch(t, bait)
	c := helper(t, "ghost-read", bait)
	select {
	case o := <-ch:
		if !o.ghost || len(o.pids) != 1 || o.pids[0] != uint32(c.Process.Pid) {
			t.Fatalf("reported %+v, want a ghost open by %d", o, c.Process.Pid)
		}
		if o.ahead && o.got {
			t.Fatal("reported ahead of letting go, yet it had already read the bait")
		}
		t.Logf("ghost opener %d attributed (ahead of the read: %v)", c.Process.Pid, o.ahead)
	case <-time.After(10 * time.Second):
		t.Fatal("the ghost open went unnoticed")
	}
}

// Same, for the variant that never asks for read access at all: open for
// execute, map the file, read the mapping. (Mapping isn't held back by the
// oplock, so this one may have the content already; it's still attributed.)
func TestGhostExecuteMappingIsAttributed(t *testing.T) {
	bait := newBait(t)
	_, ch := watch(t, bait)
	c := helper(t, "ghost-map", bait)
	select {
	case o := <-ch:
		if !o.ghost || len(o.pids) != 1 || o.pids[0] != uint32(c.Process.Pid) {
			t.Fatalf("reported %+v, want a ghost open by %d", o, c.Process.Pid)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the ghost open went unnoticed")
	}
	waitFile(t, bait+".ready")
	if b, _ := os.ReadFile(bait + ".got"); string(b) != "email / " {
		t.Fatalf("the helper should have read the bait through an execute-only mapping, got %q", b)
	}
}

// A program that merely holds an attribute-only handle on a bait (that breaks
// no oplock) must never be mistaken for the opener.
func TestAttributeHolderIsNotTheOpener(t *testing.T) {
	bait := newBait(t)
	before := helper(t, "hold-attrs", bait) // holds it before the guard is armed
	waitFile(t, bait+".ready")
	_, ch := watch(t, bait)
	os.Remove(bait + ".ready")
	after := helper(t, "hold-attrs", bait) // and one that turns up afterwards
	waitFile(t, bait+".ready")
	select {
	case o := <-ch:
		t.Fatalf("an attribute-only open was reported: %+v", o)
	case <-time.After(400 * time.Millisecond):
	}
	reader := exec.Command("cmd.exe", "/c", "type", bait, ">", bait+".out")
	reader.Start()
	defer reader.Wait()
	select {
	case o := <-ch:
		for _, p := range o.pids {
			if p == uint32(before.Process.Pid) || p == uint32(after.Process.Pid) {
				t.Fatalf("a program only holding the file was blamed for the read: %+v", o)
			}
		}
		if o.ghost {
			t.Fatalf("a normal read was reported as a ghost open: %+v", o)
		}
		t.Logf("reported %v (reader %d)", o.pids, reader.Process.Pid)
	case <-time.After(10 * time.Second):
		t.Fatal("watcher never saw the read")
	}
}

// Keeping a bait open stops ABA from guarding it. That mustn't be silent.
func TestHeldBaitIsReported(t *testing.T) {
	old := blockedAfter
	blockedAfter = 2
	defer func() { blockedAfter = old }()
	bait := newBait(t)
	blocked := make(chan []uint32, 2)
	w := &Watcher{Self: uint32(os.Getpid()), OnBlocked: func(_ string, pids []uint32) { blocked <- pids }}
	c := helper(t, "hold-read", bait)
	waitFile(t, bait+".ready")
	w.Sync([]string{bait})
	defer w.Stop()
	select {
	case pids := <-blocked:
		if len(pids) != 1 || pids[0] != uint32(c.Process.Pid) {
			t.Fatalf("blocked by %v, want %d", pids, c.Process.Pid)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a bait held open by another program was never reported")
	}
	if w.Armed() != 0 || w.Count() != 1 {
		t.Fatalf("armed %d of %d; the held bait isn't guarded", w.Armed(), w.Count())
	}
}

// Asking Windows who holds a file runs on every bait open, alongside the 60 ms
// the watcher waits anyway: it has to fit in roughly that.
func TestUsersIsQuickEnough(t *testing.T) {
	bait := newBait(t)
	g, err := Arm(bait)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Release()
	start := time.Now()
	for i := 0; i < 20; i++ {
		g.Users()
	}
	per := time.Since(start) / 20
	t.Logf("Users: %v per call", per)
	if per > 500*time.Millisecond {
		t.Fatalf("too slow to run on every bait open: %v", per)
	}
	if got := g.NewUsers(0); len(got) != 0 {
		t.Fatalf("nobody else has it open: %v", got)
	}
}
