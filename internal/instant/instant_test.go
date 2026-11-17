package instant

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// The full trick on a throwaway file, no admin needed: a reader opens the
// bait, the watcher pinpoints it while it's paused, we freeze it, release
// the oplock, and it must have read nothing.
func TestFreezeBeforeRead(t *testing.T) {
	const runs = 10
	exact, found := 0, 0
	for i := 0; i < runs; i++ {
		dir := t.TempDir()
		bait := filepath.Join(dir, "passwords.txt")
		stolen := filepath.Join(dir, "stolen.txt")
		os.WriteFile(bait, []byte("email / hunter2\r\n"), 0o644)

		var mu sync.Mutex
		var reader *exec.Cmd
		var gotPIDs []uint32
		frozen := map[uint32]bool{}
		opened := make(chan struct{}, 4)

		w := &Watcher{Self: uint32(os.Getpid())}
		w.OnOpen = func(path string, at time.Time, pids []uint32) {
			mu.Lock()
			defer mu.Unlock()
			gotPIDs = pids
			if reader != nil {
				for _, p := range pids {
					if p == uint32(reader.Process.Pid) { // in ABA: "is it suspicious?"
						procinfo.Suspend(p)
						frozen[p] = true
					}
				}
			}
			opened <- struct{}{}
		}
		w.Sync([]string{bait})
		time.Sleep(100 * time.Millisecond) // let the guard arm

		mu.Lock()
		reader = exec.Command("cmd.exe", "/c", "type", bait, ">", stolen)
		if err := reader.Start(); err != nil {
			mu.Unlock()
			t.Fatal(err)
		}
		mu.Unlock()
		rpid := uint32(reader.Process.Pid)

		select {
		case <-opened:
		case <-time.After(10 * time.Second):
			t.Fatal("watcher never saw the open")
		}
		time.Sleep(400 * time.Millisecond)
		b, _ := os.ReadFile(stolen)

		mu.Lock()
		hit := frozen[rpid]
		pids := gotPIDs
		mu.Unlock()
		if hit {
			found++
			if len(pids) == 1 {
				exact++
			}
			if len(b) != 0 {
				t.Fatalf("run %d: reader was frozen but still got %d bytes", i, len(b))
			}
			procinfo.Resume(rpid)
		}
		reader.Wait()
		w.Stop()
		t.Logf("run %d: candidates %v, reader %d pinpointed: %v, bytes before release: %d", i, pids, rpid, hit, len(b))
	}
	t.Logf("pinpointed the reader in %d/%d runs (%d with no other candidate)", found, runs, exact)
	if found < runs*8/10 {
		t.Fatalf("pinpointed the reader in only %d/%d runs", found, runs)
	}
}

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
