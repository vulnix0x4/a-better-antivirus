package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeInstall points Apply at a program folder and an updates folder of the
// test's own, with a fake service whose starts fail failStarts times. It
// returns the updates folder and a log of what happened, in order.
func fakeInstall(t *testing.T, failStarts int) (updates string, log *[]string) {
	t.Helper()
	old := []any{dirOf, cliTarget, serviceTarget, poolsTarget, serviceStop, serviceStart}
	t.Cleanup(func() {
		dirOf, cliTarget, serviceTarget, poolsTarget = old[0].(func() string), old[1].(func() string), old[2].(func() string), old[3].(func() string)
		serviceStop, serviceStart = old[4].(func() error), old[5].(func() error)
	})
	prog := t.TempDir()
	updates = t.TempDir()
	var l []string
	log = &l
	dirOf = func() string { return updates }
	cliTarget = func() string { return filepath.Join(prog, "aba.exe") }
	serviceTarget = func() string { return filepath.Join(prog, "famsvc.exe") }
	poolsTarget = func() string { return filepath.Join(prog, "pools.txt") }
	serviceStop = func() error { l = append(l, "stop"); return nil }
	serviceStart = func() error {
		l = append(l, "start service "+read(t, serviceTarget()))
		if failStarts > 0 {
			failStarts--
			return errors.New("didn't start")
		}
		return nil
	}
	os.WriteFile(cliTarget(), []byte("old program"), 0o755)
	os.WriteFile(serviceTarget(), []byte("old program"), 0o755)
	return updates, log
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return "(none)"
	}
	return string(b)
}

// stage puts a verified download (and its app) in the updates folder.
func stage(t *testing.T, updates string) string {
	src := filepath.Join(updates, "aba-v9.9.9.exe")
	os.WriteFile(src, []byte("new program"), 0o755)
	os.WriteFile(AppBeside(src), []byte("new app"), 0o755)
	return src
}

func TestApplyInstallsTheAppAfterTheProgram(t *testing.T) {
	target, _ := fakeApp(t, true)
	updates, log := fakeInstall(t, 0)
	os.WriteFile(target, []byte("old app"), 0o755)
	inner := appInstall
	appInstall = func(src string) error {
		*log = append(*log, "install app (service binary: "+read(t, serviceTarget())+")")
		return inner(src)
	}
	if err := Apply(stage(t, updates), nil); err != nil {
		t.Fatal(err)
	}
	want := "stop | install app (service binary: new program) | start service new program"
	if got := strings.Join(*log, " | "); got != want {
		t.Errorf("order:\n got %s\nwant %s", got, want)
	}
	if read(t, target) != "new app" || read(t, cliTarget()) != "new program" {
		t.Errorf("after the update: app %q, aba.exe %q", read(t, target), read(t, cliTarget()))
	}
}

func TestApplyPutsTheAppBackWhenTheServiceFails(t *testing.T) {
	target, _ := fakeApp(t, true)
	updates, log := fakeInstall(t, 1)
	os.WriteFile(target, []byte("old app"), 0o755)
	if err := Apply(stage(t, updates), nil); err == nil {
		t.Fatal("a service that didn't start: no error")
	}
	if got := strings.Join(*log, " | "); got != "stop | start service new program | start service old program" {
		t.Errorf("order: %s", got)
	}
	if read(t, target) != "old app" || read(t, serviceTarget()) != "old program" {
		t.Errorf("after the rollback: app %q, service %q", read(t, target), read(t, serviceTarget()))
	}
}

func TestApplyRollbackTakesAwayAnAppItAdded(t *testing.T) {
	target, _ := fakeApp(t, true)
	updates, _ := fakeInstall(t, 1)
	if err := Apply(stage(t, updates), nil); err == nil {
		t.Fatal("a service that didn't start: no error")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the app the failed update added is still there: %v", err)
	}
	if left, _ := filepath.Glob(target + ".old-*"); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestApplyWithoutAnAppLeavesItAlone(t *testing.T) {
	target, installs := fakeApp(t, true)
	updates, _ := fakeInstall(t, 1)
	os.WriteFile(target, []byte("old app"), 0o755)
	src := filepath.Join(updates, "aba-v9.9.9.exe")
	os.WriteFile(src, []byte("new program"), 0o755) // a version from before the app
	Apply(src, nil)
	if *installs != 0 || read(t, target) != "old app" {
		t.Errorf("installs %d, app %q", *installs, read(t, target))
	}
}
