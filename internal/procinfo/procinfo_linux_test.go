package procinfo

import (
	"os"
	"testing"
)

func TestParseStat(t *testing.T) {
	// A name with spaces and brackets in it, as a program may give itself.
	st, err := parseStat("4242 (my (odd) name) S 17 4242 4242 34819 4242 4194304 1 2 3 4 5 6 7 8 20 0 1 0 987654 1000 2000 18446744073709551615")
	if err != nil {
		t.Fatal(err)
	}
	if st.Comm != "my (odd) name" || st.State != 'S' || st.PPID != 17 || st.TTY != 34819 || st.StartTime != 987654 {
		t.Fatalf("got %+v", st)
	}
	if _, err := parseStat("garbage"); err == nil {
		t.Fatal("garbage should not parse")
	}
}

func TestSelf(t *testing.T) {
	pid := uint32(os.Getpid())
	ct, err := CreateTime(pid)
	if err != nil || ct <= 0 {
		t.Fatalf("CreateTime: %d, %v", ct, err)
	}
	if !Alive(pid, ct) || Alive(pid, ct+1) {
		t.Fatal("Alive should go by the start time")
	}
	img, err := ImagePath(pid)
	if err != nil || img == "" {
		t.Fatalf("ImagePath: %q, %v", img, err)
	}
	if exe, _ := os.Executable(); exe != img {
		t.Fatalf("ImagePath = %q, the test binary is %q", img, exe)
	}
	args, err := Args(pid)
	if err != nil || len(args) == 0 {
		t.Fatalf("Args: %q, %v", args, err)
	}
	snap, err := Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	me, ok := snap[pid]
	if !ok || me.PPID != uint32(os.Getppid()) || me.CreateTime != ct {
		t.Fatalf("snapshot entry %+v", me)
	}
	if systemPID(pid) || !systemPID(1) || !systemPID(2) {
		t.Fatal("systemPID")
	}
	if Elevated(pid) != (os.Geteuid() == 0) {
		t.Fatalf("Elevated = %v as uid %d", Elevated(pid), os.Geteuid())
	}
	if id, err := UserID(pid); err != nil || id == "" {
		t.Fatalf("UserID: %q, %v", id, err)
	}
	if ParentPID(pid) != uint32(os.Getppid()) {
		t.Fatal("ParentPID")
	}
	// The test binary lives in a temp folder: code nobody vouches for.
	if os.Geteuid() != 0 {
		if f, found := ForeignCode(pid); !found {
			t.Fatalf("ForeignCode should name the test binary itself, got %q", f)
		}
	}
}

func TestServiceAccounts(t *testing.T) {
	for id, want := range map[string]bool{"0": true, "33": true, "65534": true, "1000": false, "x": true} {
		if got := ServiceAccount(id); got != want {
			t.Errorf("ServiceAccount(%s) = %v", id, got)
		}
	}
}

func TestSockAddrAndArgs(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:0035":                         "127.0.0.1:53",
		"00000000:0000":                         "0.0.0.0:0",
		"00000000000000000000000001000000:01BB": "[::1]:443",
	} {
		if got := sockAddr(in); got != want {
			t.Errorf("sockAddr(%s) = %s, want %s", in, got, want)
		}
	}
	if got := JoinArgs([]string{"python3", "my script.py", "it's"}); got != `python3 'my script.py' 'it'\''s'` {
		t.Errorf("JoinArgs = %s", got)
	}
	if got := unescape(`/mnt/my\040disk`); got != "/mnt/my disk" {
		t.Errorf("unescape = %q", got)
	}
}
