package instant

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestStuckThreadsAndTick(t *testing.T) {
	ts, err := StuckThreads(0)
	if err != nil || len(ts) == 0 {
		t.Fatalf("StuckThreads: %d, %v", len(ts), err)
	}
	a := Tick()
	time.Sleep(100 * time.Millisecond)
	if d := Tick() - a; d < 3 || d > 20 {
		t.Fatalf("tick advanced %d in 100ms; expected ~6", d)
	}
}

// Deleting a bait or checking its permissions must not look like a read.
func TestNonReadOpensAreLetThrough(t *testing.T) {
	dir := t.TempDir()
	bait := filepath.Join(dir, "passwords.txt")
	os.WriteFile(bait, []byte("x"), 0o644)
	reads, others := make(chan []uint32, 4), make(chan uint32, 4)
	w := &Watcher{Self: uint32(os.Getpid()),
		OnOpen:  func(_ string, _ time.Time, pids []uint32) { reads <- pids },
		OnOther: func(_ string, access uint32) { others <- access }}
	w.Sync([]string{bait})
	defer w.Stop()
	time.Sleep(100 * time.Millisecond)

	// A delete from another process.
	del := exec.Command("cmd.exe", "/c", "del", "/q", bait)
	if err := del.Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-others:
		t.Logf("delete open let through (access 0x%x)", a)
	case <-reads:
		t.Fatal("a delete was treated as a read")
	case <-time.After(5 * time.Second):
		t.Fatal("no break for the delete")
	}
	if _, err := os.Stat(bait); !os.IsNotExist(err) {
		t.Fatal("delete didn't go through")
	}
	if !WantsContents(0x80000000) || !WantsContents(0x1) || WantsContents(0x00110080) {
		t.Fatal("WantsContents mask logic")
	}
}

// ABA reading its own bait (the health check does) must not be blamed on
// whatever other program happens to wake at that moment.
func TestOwnReadIsNotBlamedOnOthers(t *testing.T) {
	for i := 0; i < 5; i++ {
		dir := t.TempDir()
		bait := filepath.Join(dir, "passwords.txt")
		os.WriteFile(bait, []byte("email / hunter2\r\n"), 0o644)
		got := make(chan []uint32, 4)
		w := &Watcher{Self: uint32(os.Getpid()), OnOpen: func(_ string, _ time.Time, pids []uint32) { got <- pids }}
		w.Sync([]string{bait})
		time.Sleep(100 * time.Millisecond)

		// Bystanders that keep starting short waits, like a busy program would.
		stop := make(chan struct{})
		var bys []*exec.Cmd
		for j := 0; j < 3; j++ {
			c := exec.Command("ping.exe", "-n", "4", "127.0.0.1")
			c.Start()
			bys = append(bys, c)
		}
		if _, err := os.ReadFile(bait); err != nil { // our own read
			t.Fatal(err)
		}
		select {
		case pids := <-got:
			if len(pids) != 0 {
				t.Fatalf("run %d: our own read was blamed on %v", i, pids)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("watcher never saw the open")
		}
		close(stop)
		for _, c := range bys {
			c.Process.Kill()
			c.Wait()
		}
		w.Stop()
	}
}

// The CI hang taught us an innocent thread can start a long wait at the same
// moment as the opener (e.g. a runner reading a pipe). Only the opener wakes
// when ABA lets go, so only it may be reported.
func TestPinpointsOpenerNotBystander(t *testing.T) {
	const runs = 10
	exact := 0
	for i := 0; i < runs; i++ {
		dir := t.TempDir()
		bait := filepath.Join(dir, "passwords.txt")
		os.WriteFile(bait, []byte("email / hunter2\r\n"), 0o644)

		got := make(chan []uint32, 4)
		w := &Watcher{Self: uint32(os.Getpid()), OnOpen: func(_ string, _ time.Time, pids []uint32) { got <- pids }}
		w.Sync([]string{bait})
		time.Sleep(100 * time.Millisecond)

		// Bystander: blocks reading an empty pipe, started together with the reader.
		pr, pw, _ := os.Pipe()
		by := exec.Command("findstr.exe", "x")
		by.Stdin = pr
		reader := exec.Command("cmd.exe", "/c", "type", bait, ">", filepath.Join(dir, "out.txt"))
		by.Start()
		reader.Start()

		var pids []uint32
		select {
		case pids = <-got:
		case <-time.After(10 * time.Second):
			t.Fatal("watcher never saw the open")
		}
		rpid, bpid := uint32(reader.Process.Pid), uint32(by.Process.Pid)
		hasReader, hasBystander := false, false
		for _, p := range pids {
			hasReader = hasReader || p == rpid
			hasBystander = hasBystander || p == bpid
		}
		if hasBystander {
			t.Fatalf("run %d: innocent bystander %d reported as the opener (%v)", i, bpid, pids)
		}
		if hasReader && len(pids) == 1 {
			exact++
		}
		t.Logf("run %d: reported %v (reader %d, bystander %d)", i, pids, rpid, bpid)
		reader.Wait()
		pw.Close()
		by.Wait()
		w.Stop()
	}
	t.Logf("reported exactly the reader in %d/%d runs; never the bystander", exact, runs)
	if exact < runs*7/10 {
		t.Fatalf("pinpointed the reader alone in only %d/%d runs", exact, runs)
	}
}
