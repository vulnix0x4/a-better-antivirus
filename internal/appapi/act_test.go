package appapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var testExists = Exists{
	Alert: func(id string) bool { return id == "20261127-140207-7f3a" },
	Bait:  func(id string) bool { return id == "discord" || id == "custom-1a2b3c4d" },
}

func TestCommand(t *testing.T) {
	const id = "20261127-140207-7f3a"
	ok := []struct {
		kind, id, arg string
		want          []string
	}{
		{"kill", id, "", []string{"kill", "--json", "--yes", "--", id}},
		{"resume", id, "", []string{"resume", "--json", "--yes", "--", id}},
		{"trust", id, "", []string{"trust", "--json", "--yes", "--", id}},
		{"release", "", "", []string{"release", "--json", "--yes"}},
		{"release", id, "", []string{"release", "--json", "--yes", "--", id}},
		{"instant", "", "off", []string{"instant", "off", "--json", "--yes"}},
		{"clipboard", "", "on", []string{"clipboard", "on", "--json", "--yes"}},
		{"miners", "", "off", []string{"miners", "off", "--json", "--yes"}},
		{"recorder", "", "on", []string{"recorder", "on", "--json", "--yes"}},
		{"auto-update", "", "off", []string{"update", "auto", "off", "--json", "--yes"}},
		{"preset", "", "strict", []string{"preset", "strict", "--json", "--yes"}},
		{"bait-show", "discord", "", []string{"bait", "show", "--json", "--yes", "--", "discord"}},
		{"bait-show", "custom-1a2b3c4d", "", []string{"bait", "show", "--json", "--yes", "--", "custom-1a2b3c4d"}},
		{"test", "", "", []string{"test", "--json", "--yes"}},
		{"update-check", "", "", []string{"update", "--check", "--json", "--yes"}},
		{"update", "", "", []string{"update", "--json", "--yes"}},
		{"phone-test", "", "", []string{"phone", "test", "--json", "--yes"}},
	}
	for _, c := range ok {
		got, err := Command(c.kind, c.id, c.arg, testExists)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %q %q: got %q, %v; want %q", c.kind, c.id, c.arg, got, err, c.want)
		}
	}
	bad := []struct{ kind, id, arg string }{
		{"", "", ""},
		{"uninstall", "x", ""},
		{"KILL", id, ""},
		{"kill", "", ""},
		{"kill", "20261127-140207-0000", ""}, // well formed, not on disk
		{"kill", "7f3a", ""},                 // a short ID: Load would match by suffix
		{"kill", "--all", ""},
		{"kill", id + " --x", ""},
		{"kill", id + "\x00", ""},
		{"kill", `..\..\config`, ""},
		{"kill", id, "--force"},
		{"trust", "-h", ""},
		{"release", "x", ""},
		{"release", "", "all"},
		{"instant", "", "maybe"},
		{"instant", "", "on --json"},
		{"instant", id, "on"},
		{"preset", "", "custom"},
		{"preset", "", "strict; del"},
		{"preset", "x", "strict"},
		{"auto-update", "", ""},
		{"bait-show", "Discord", ""},
		{"bait-show", "../state", ""},
		{"bait-show", "-x", ""},
		{"bait-show", "telegram", ""}, // not planted
		{"bait-show", "discord", "x"},
		{"test", id, ""},
		{"update", "", "--file=C:\\evil.exe"},
		{"phone-test", "", "x"},
	}
	for _, c := range bad {
		if got, err := Command(c.kind, c.id, c.arg, testExists); err == nil {
			t.Errorf("%q %q %q: allowed (%q)", c.kind, c.id, c.arg, got)
		}
	}
	if _, err := Command("kill", id, "", Exists{}); err == nil {
		t.Error("no existence check: allowed")
	}
}

func TestValidIDs(t *testing.T) {
	for _, id := range []string{"20261127-140207-7f3a", "20261127-140207-deadbeef"} {
		if !ValidAlertID(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, id := range []string{"", "x", "20261127-140207-7F3A", "20261127-140207-7f3a.json", "20261127-140207-7f3a/..", "../20261127-140207-7f3a", "20261127_140207-7f3a"} {
		if ValidAlertID(id) {
			t.Errorf("%q allowed", id)
		}
	}
	for _, id := range []string{"discord", "chrome-profile", "custom-1a2b3c4d", "ssh-backup"} {
		if !ValidBaitID(id) {
			t.Errorf("%q refused", id)
		}
	}
	for _, id := range []string{"", "-x", "Discord", "a/b", `a\b`, "a b", "a.b", strings.Repeat("a", 65)} {
		if ValidBaitID(id) {
			t.Errorf("%q allowed", id)
		}
	}
}

// fakeRunner answers like the CLI would.
func fakeRunner(lines ...string) (Runner, *[][]string) {
	var calls [][]string
	return func(ctx context.Context, exe string, args []string, stdin []byte, line func(string)) error {
		calls = append(calls, append([]string{exe}, args...))
		for _, l := range lines {
			line(l)
		}
		return nil
	}, &calls
}

func TestActRunsCLI(t *testing.T) {
	run, calls := fakeRunner(
		`{"event":"step","text":"A harmless fake stealer is about to read password list on the Desktop.","time":"2026-11-27T14:00:00Z"}`,
		`{"event":"step","text":"Caught and frozen.","time":"2026-11-27T14:00:01Z"}`,
		`{"ok":true,"message":"Caught it in 0.1 s.","details":{"alertId":"20261127-140001-aaaa"}}`)
	a := &Actor{CLI: `C:\Program Files\File Access Monitor\aba.exe`, Exists: testExists, Run: run}
	res := a.Act("test", "", "")
	if !res.OK || res.Message != "Caught it in 0.1 s." || res.Details == nil {
		t.Fatalf("got %+v", res)
	}
	if want := []string{`C:\Program Files\File Access Monitor\aba.exe`, "test", "--json", "--yes"}; !reflect.DeepEqual((*calls)[0], want) {
		t.Fatalf("ran %q", (*calls)[0])
	}
	p := a.Progress()
	if p.Running || p.Kind != "test" || len(p.Events) != 3 || p.Events[2].Event != "done" {
		t.Fatalf("progress %+v", p)
	}
}

func TestActRefusesBeforeRunning(t *testing.T) {
	run, calls := fakeRunner(`{"ok":true,"message":"x"}`)
	a := &Actor{CLI: `C:\aba.exe`, Exists: testExists, Run: run}
	if res := a.Act("kill", "--all", ""); res.OK {
		t.Fatal("bad ID ran")
	}
	if len(*calls) != 0 {
		t.Fatalf("ran %q", *calls)
	}
}

func TestActBadOutput(t *testing.T) {
	for _, lines := range [][]string{
		nil,
		{"something went wrong"},
		{`{"message":"no ok"}`},
		{`{"ok":tru`},
	} {
		run, _ := fakeRunner(lines...)
		a := &Actor{CLI: `C:\aba.exe`, Exists: testExists, Run: run}
		if res := a.Act("phone-test", "", ""); res.OK || res.Message == "" {
			t.Errorf("%q: got %+v", lines, res)
		}
	}
	a := &Actor{CLI: `C:\aba.exe`, Exists: testExists, Run: func(context.Context, string, []string, []byte, func(string)) error {
		return errors.New("exit status 1")
	}}
	if res := a.Act("phone-test", "", ""); res.OK || !strings.Contains(res.Message, "exit status 1") {
		t.Errorf("got %+v", res)
	}
}

func TestActOneAtATime(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	a := &Actor{CLI: `C:\aba.exe`, Exists: testExists, Run: func(ctx context.Context, exe string, args []string, stdin []byte, line func(string)) error {
		close(started)
		<-release
		line(`{"ok":true,"message":"done"}`)
		return nil
	}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.Act("test", "", "") }()
	<-started
	if res := a.Act("phone-test", "", ""); res.OK || !strings.Contains(res.Message, "busy") {
		t.Fatalf("second action ran: %+v", res)
	}
	if !a.Progress().Running {
		t.Fatal("not running")
	}
	close(release)
	wg.Wait()

}
