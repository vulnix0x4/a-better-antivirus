package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/fanwatch"
)

// A bait deleted, replaced, or taken away with its folder is reported the
// moment it happens, naming the process that did it. ABA's own changes
// aren't.
func TestBaitFoldersWatched(t *testing.T) {
	requireRoot(t)
	cred := player(t)
	home := sandbox(t)
	app := filepath.Join(home, ".config", "someapp")
	os.MkdirAll(app, 0o777)
	os.Chmod(filepath.Join(home, ".config"), 0o777)
	os.Chmod(app, 0o777)
	b := bait(t, app)
	d, err := fanwatch.NewDirs()
	if err != nil {
		t.Fatalf("the runner's kernel can watch folders: %v", err)
	}
	t.Cleanup(d.Close)
	changes := make(chan fanwatch.Change, 8)
	d.OnChange = func(c fanwatch.Change) { changes <- c }
	if errs := d.Sync([]string{b}, home); len(errs) > 0 {
		t.Fatal(errs)
	}
	go d.Run()
	next := func(what string) (fanwatch.Change, bool) {
		select {
		case c := <-changes:
			return c, true
		case <-time.After(5 * time.Second):
			t.Errorf("%s: not reported", what)
			return fanwatch.Change{}, false
		}
	}

	// Our own changes: not reported.
	os.Remove(b)
	select {
	case c := <-changes:
		t.Fatalf("the watcher's own delete was reported: %+v", c)
	case <-time.After(300 * time.Millisecond):
	}
	b = bait(t, app)
	d.Sync([]string{b}, home)

	marker := filepath.Join(home, "m")
	cmd := helper(t, cred, "delete", b, marker, 0)
	if c, ok := next("a delete by another program"); ok {
		if c.PID != uint32(cmd.Process.Pid) || c.What != "deleted" || len(c.Baits) != 1 || c.Baits[0] != b {
			t.Fatalf("got %+v, want pid %d deleting %s", c, cmd.Process.Pid, b)
		}
	}

	b = bait(t, app)
	d.Sync([]string{b}, home)
	other := filepath.Join(app, "other")
	os.WriteFile(other, []byte("x"), 0o666)
	if err := os.Rename(other, b); err != nil {
		t.Fatal(err)
	}
	// (Done by this process: not reported. Ask the kernel through a helper
	// instead: rename isn't a helper mode, so move the folder as the user.)
	time.Sleep(200 * time.Millisecond)
	for len(changes) > 0 {
		<-changes
	}
	mv := helperRename(t, cred, app, app+"-moved")
	if c, ok := next("its folder renamed away"); ok {
		if c.PID != uint32(mv) || c.What != "renamed away" || c.Path != app {
			t.Fatalf("got %+v, want pid %d moving %s", c, mv, app)
		}
	}
}

// helperRename renames old to new as cred (with mv), and returns mv's PID.
func helperRename(t *testing.T, cred *syscall.Credential, old, new string) int {
	t.Helper()
	c := exec.Command("/bin/mv", old, new)
	c.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	if err := c.Wait(); err != nil {
		t.Fatalf("mv: %v", err)
	}
	return pid
}
