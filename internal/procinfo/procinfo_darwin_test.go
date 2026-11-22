package procinfo

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func TestDarwinSelf(t *testing.T) {
	me := uint32(os.Getpid())
	snap, err := Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := snap[me]
	if !ok {
		t.Fatal("this process isn't in the snapshot")
	}
	if e.PPID != uint32(os.Getppid()) {
		t.Errorf("parent %d, want %d", e.PPID, os.Getppid())
	}
	ct, err := CreateTime(me)
	if err != nil || ct == 0 || ct != e.CreateTime {
		t.Errorf("create time %d (%v), snapshot says %d", ct, err, e.CreateTime)
	}
	if !Alive(me, ct) || Alive(me, ct+1) {
		t.Error("Alive doesn't tell this process from another with the same PID")
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	if img, err := ImagePath(me); err != nil || img != exe {
		t.Errorf("image %q (%v), want %q", img, err, exe)
	}
	if args, err := Args(me); err != nil || !reflect.DeepEqual(args, os.Args) {
		t.Errorf("args %q (%v), want %q", args, err, os.Args)
	}
	wd, _ := os.Getwd()
	wd, _ = filepath.EvalSymlinks(wd)
	if cwd := Cwd(me); cwd != wd {
		t.Errorf("cwd %q, want %q", cwd, wd)
	}
	if ParentPID(me) != uint32(os.Getppid()) {
		t.Error("ParentPID")
	}
	id, err := UserID(me)
	if err != nil || id != strconv.Itoa(os.Geteuid()) {
		t.Errorf("user %q (%v)", id, err)
	}
	if os.Geteuid() != 0 && (Elevated(me) || !UserSession(me)) {
		t.Error("an ordinary test run counts as elevated or as a service")
	}
	if !ServiceAccount("0") || !ServiceAccount("248") || ServiceAccount("501") {
		t.Error("ServiceAccount")
	}
	if found := RunningImage(exe); len(found) == 0 {
		t.Error("RunningImage doesn't find this test")
	}
}

func TestDarwinParseProcArgs(t *testing.T) {
	b := []byte{3, 0, 0, 0}
	b = append(b, "/bin/sh\x00\x00\x00\x00sh\x00-c\x00echo hi\x00PATH=/bin\x00"...)
	got, err := parseProcArgs(b)
	if err != nil || !reflect.DeepEqual(got, []string{"sh", "-c", "echo hi"}) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestDarwinParseLsof(t *testing.T) {
	out := `COMMAND   PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
curl    12345 alice    5u  IPv4 0x1234567890abcdef      0t0  TCP 192.168.1.5:50123->93.184.216.34:443 (ESTABLISHED)
curl    12345 alice    6u  IPv6 0x1234567890abcdee      0t0  UDP *:5353
`
	got := parseLsof(out)
	want := []Conn{
		{PID: 12345, Proto: "tcp", Local: "192.168.1.5:50123", Remote: "93.184.216.34:443", State: "ESTABLISHED"},
		{PID: 12345, Proto: "udp6", Local: "*:5353"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}

func TestDarwinRecent(t *testing.T) {
	Remember(RecentProcess{PID: 4_000_000, PPID: 77, Image: "/bin/cat", Args: []string{"cat", "x"}})
	if img, err := ImagePath(4_000_000); err != nil || img != "/bin/cat" {
		t.Errorf("an exited process's image: %q %v", img, err)
	}
	if ParentPID(4_000_000) != 77 {
		t.Error("an exited process's parent")
	}
}
