package netrec

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/etw"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// Needs an elevated shell and the internet: ABA_INTEGRATION=1.
func TestWatchSeesWhatLeaves(t *testing.T) {
	if os.Getenv("ABA_INTEGRATION") == "" {
		t.Skip("set ABA_INTEGRATION=1 (elevated, online)")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated shell")
	}
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Watch(ctx, r, t.Logf) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("watch: %v", err)
		}
		if r.Status().Running {
			t.Error("still running after it stopped")
		}
	}()
	for i := 0; !r.Status().Running; i++ {
		if i > 100 {
			t.Fatalf("not running: %s", r.Status().Why)
		}
		time.Sleep(50 * time.Millisecond)
	}
	from := time.Now()

	// Loopback: never kept.
	if l, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		go func() {
			if c, err := l.Accept(); err == nil {
				io.Copy(io.Discard, c)
			}
		}()
		if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
			c.Write([]byte("loopback"))
			c.Close()
		}
		defer l.Close()
	}

	// This process: a request to example.com.
	c, err := net.DialTimeout("tcp", "example.com:80", 10*time.Second)
	if err != nil {
		t.Skipf("offline? %v", err)
	}
	req := "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
	c.Write([]byte(req))
	io.Copy(io.Discard, c)
	c.Close()

	// A program it starts: curl, to example.org.
	cmd := exec.Command(`C:\Windows\System32\curl.exe`, "-s", "-o", "NUL", "http://example.org/")
	if err := cmd.Run(); err != nil {
		t.Logf("curl: %v", err)
	}
	child := uint32(cmd.ProcessState.Pid())

	self := uint32(os.Getpid())
	start, err := procinfo.StartedAt(self)
	if err != nil {
		t.Fatal(err)
	}
	res := r.Query(Query{Members: []Member{{PID: self, Start: start}}, From: start, To: time.Now()})
	if res.Behind {
		t.Error("couldn't catch up")
	}
	if len(res.Lapses) > 0 {
		t.Logf("lapses: %+v", res.Lapses)
	}
	var mine, curl bool
	for _, s := range res.Sends {
		t.Logf("pid %d %s via %q %s first %s bytes %d sends %d conns %d", s.PID, s.Image, s.Via, s.Where(), s.First.Format("15:04:05.000"), s.Bytes, s.Sends, s.Conns)
		if s.Remote.Addr().IsLoopback() {
			t.Errorf("loopback kept: %+v", s)
		}
		if s.PID == self && s.Remote.Port() == 80 && s.Bytes >= int64(len(req)) && s.Conns >= 1 {
			mine = true
			if s.Name != "example.com" {
				t.Errorf("name: %q", s.Name)
			}
			if s.First.Before(from.Add(-time.Second)) || s.First.After(time.Now()) {
				t.Errorf("time: %s (asked at %s)", s.First, from)
			}
		}
		if s.PID == child && s.Remote.Port() == 80 {
			curl = true
			if !strings.Contains(s.Via, "started by") || !strings.EqualFold(s.Image, "curl.exe") {
				t.Errorf("curl: via %q image %q", s.Via, s.Image)
			}
		}
	}
	if !mine {
		t.Error("its own request to example.com wasn't recorded")
	}
	if !curl {
		t.Error("curl's request (a program it started) wasn't recorded")
		r.mu.Lock()
		for _, p := range r.procs[child] {
			t.Logf("curl in the record: %+v", *p)
			for a, d := range p.dests {
				t.Logf("  %s %+v", a, *d)
			}
		}
		r.mu.Unlock()
	}
	st := r.Status()
	t.Logf("status: %+v", st)
}

func TestLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit only")
	}
	if n := unsafe.Sizeof(etw.EventRecord{}); n != 112 {
		t.Errorf("EVENT_RECORD is %d bytes, want 112", n)
	}
}
