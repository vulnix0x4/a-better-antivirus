package eswatch

import (
	"strings"
	"testing"
)

// Lines as eslogger writes them (trimmed: the real ones carry stat blocks
// and much more for every file and process).
const (
	openLine  = `{"action_type":1,"process":{"signing_id":"com.apple.cat","tty":{"path":"/dev/ttys003"},"ppid":53300,"codesigning_flags":637606673,"start_time":"2026-11-21T12:09:22.075857Z","is_platform_binary":true,"audit_token":{"euid":501,"pid":53306},"team_id":null,"executable":{"path":"/bin/cat"}},"event_type":10,"time":"2026-11-21T12:09:22.076352006Z","event":{"open":{"fflag":1,"file":{"path_truncated":false,"path":"/Users/a/Library/Application Support/Exodus/exodus.wallet/seed.seco"}}}}`
	writeLine = `{"process":{"audit_token":{"euid":0,"pid":1},"executable":{"path":"/x"}},"event_type":10,"time":"2026-11-21T12:09:22Z","event":{"open":{"fflag":2,"file":{"path":"/Users/a/Library/Application Support/Exodus/exodus.wallet/seed.seco"}}}}`
	cloneLine = `{"process":{"audit_token":{"euid":501,"pid":700},"ppid":1,"executable":{"path":"/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Versions/A/Resources/DesktopServicesHelper"},"is_platform_binary":true},"event_type":61,"time":"2026-11-21T12:09:22Z","event":{"clone":{"source":{"path":"/Users/a/Documents/passwords.txt"},"target_dir":{"path":"/tmp/x"},"target_name":"passwords.txt"}}}`
	linkLine  = `{"process":{"audit_token":{"euid":501,"pid":800},"executable":{"path":"/bin/ln"}},"event_type":19,"time":"2026-11-21T12:09:22Z","event":{"link":{"source":{"path":"/Users/a/Documents/passwords.txt"},"target_dir":{"path":"/tmp"},"target_filename":"p"}}}`
	execLine  = `{"process":{"audit_token":{"euid":501,"pid":900},"executable":{"path":"/bin/zsh"}},"event_type":9,"time":"2026-11-21T12:09:22Z","event":{"exec":{"args":["/bin/sh","-c","cat x"],"cwd":{"path":"/Users/a"},"fds":[{"fdtype":6,"fd":0,"pipe":{"pipe_id":4}}],"target":{"audit_token":{"euid":501,"pid":900},"ppid":899,"executable":{"path":"/bin/sh"},"is_platform_binary":true,"codesigning_flags":637606673,"tty":{"path":"/dev/ttys003"}}}}}`
)

func collect(t *testing.T, baits []string, lines ...string) ([]Event, []Exec) {
	t.Helper()
	w := New()
	w.Sync(baits)
	var evs []Event
	var execs []Exec
	w.OnEvent = func(e Event) { evs = append(evs, e) }
	w.OnExec = func(x Exec) { execs = append(execs, x) }
	w.read(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	return evs, execs
}

func TestReadsAndWrites(t *testing.T) {
	bait := "/Users/a/Library/Application Support/Exodus/exodus.wallet/seed.seco"
	evs, _ := collect(t, []string{bait}, openLine, writeLine)
	if len(evs) != 1 {
		t.Fatalf("want only the read, got %+v", evs)
	}
	e := evs[0]
	if e.Op != Read || e.Path != bait || e.Proc.PID != 53306 || e.Proc.PPID != 53300 || e.Proc.Image != "/bin/cat" ||
		!e.Proc.Platform || e.Proc.UID != 501 || e.Proc.TTY != "/dev/ttys003" || e.At.IsZero() {
		t.Errorf("%+v", e)
	}
}

func TestCopiesAndLinks(t *testing.T) {
	bait := "/Users/a/Documents/passwords.txt"
	evs, _ := collect(t, []string{bait}, cloneLine, linkLine)
	if len(evs) != 2 {
		t.Fatalf("%+v", evs)
	}
	if evs[0].Op != Read || evs[0].Kind != "clone" || !IsFinderCopier(evs[0].Proc) {
		t.Errorf("clone: %+v", evs[0])
	}
	if evs[1].Op != Link || evs[1].Alias != "/tmp/p" {
		t.Errorf("link: %+v", evs[1])
	}
	// A file that isn't a bait is never reported.
	if evs, _ := collect(t, []string{"/Users/a/other.txt"}, cloneLine, linkLine, openLine); len(evs) != 0 {
		t.Errorf("not a bait: %+v", evs)
	}
}

func TestExec(t *testing.T) {
	_, execs := collect(t, nil, execLine)
	if len(execs) != 1 {
		t.Fatalf("%+v", execs)
	}
	x := execs[0]
	if x.Proc.PID != 900 || x.Proc.PPID != 899 || x.Proc.Image != "/bin/sh" || x.Cwd != "/Users/a" || len(x.Args) != 3 || x.Stdin != "" {
		t.Errorf("%+v", x)
	}
}

func TestFinderLogLine(t *testing.T) {
	f := &FinderLog{senders: map[uint32]Sender{}}
	f.line([]byte(`{"eventMessage":"TCC RESULT: [sess=1 pid=1 uid:501,auid:501] ACCESS GRANTED","timestamp":"2026-11-21 06:02:30.167123-0700"}`))
	if s := f.Suspects(); len(s) != 1 || s[0].PID != 1 || s[0].Image != "/sbin/launchd" {
		t.Errorf("%+v", s)
	}
}
