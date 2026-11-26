package netrec

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

var (
	t0     = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	remote = netip.MustParseAddrPort("162.159.135.232:443")
)

func query(r *Record, pid uint32, start time.Time) Result {
	return r.Query(Query{Members: []Member{{PID: pid, Start: start}}, From: start, To: t0.Add(time.Hour)})
}

func TestBurstsAndSince(t *testing.T) {
	r := New()
	r.Began(t0, nil)
	r.Started(10, 1, t0, "x.exe")
	r.Send(t0.Add(1*time.Second), 10, remote, 100, false, false)
	r.Send(t0.Add(1500*time.Millisecond), 10, remote, 100, false, false) // same burst
	r.Send(t0.Add(10*time.Second), 10, remote, 1000, false, false)       // a new one
	res := query(r, 10, t0)
	if len(res.Sends) != 1 {
		t.Fatalf("sends = %+v", res.Sends)
	}
	s := res.Sends[0]
	if s.Bytes != 1200 || s.Sends != 3 || !s.First.Equal(t0.Add(time.Second)) || !s.Last.Equal(t0.Add(10*time.Second)) {
		t.Errorf("send = %+v", s)
	}
	if b, any := s.Since(t0.Add(5 * time.Second)); !any || b != 1000 {
		t.Errorf("since 5 s: %d %v", b, any)
	}
	if b, any := s.Since(t0.Add(1200 * time.Millisecond)); !any || b != 1200 {
		t.Errorf("a burst that began before is counted whole: %d %v", b, any)
	}
	if _, any := s.Since(t0.Add(11 * time.Second)); any {
		t.Error("nothing after the last send")
	}
}

func TestBounded(t *testing.T) {
	r := New()
	r.Began(t0, nil)
	r.Started(10, 1, t0, "x.exe")
	for i := 0; i < maxDests+10; i++ {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}), 443)
		for j := 0; j < maxBursts+5; j++ {
			r.Send(t0.Add(time.Duration(j)*10*time.Second), 10, a, 10, false, false)
		}
	}
	res := query(r, 10, t0)
	if len(res.Sends) != maxDests+1 {
		t.Fatalf("%d sends, want %d and one for the rest", len(res.Sends), maxDests+1)
	}
	var other *Send
	for i, s := range res.Sends {
		if !s.Remote.IsValid() {
			other = &res.Sends[i]
		}
		if len(s.bursts) > maxBursts+1 {
			t.Errorf("%d bursts kept", len(s.bursts))
		}
	}
	if other == nil || other.Bytes != 10*10*(maxBursts+5) || other.Where() != "other addresses" {
		t.Errorf("the rest: %+v", other)
	}
	if res.Sends[0].Bytes != 10*(maxBursts+5) {
		t.Errorf("merged bursts lost bytes: %+v", res.Sends[0])
	}
}

// A send heard before its process's start (reports out of order) is still
// that process's.
func TestStartHeardAfterSend(t *testing.T) {
	r := New()
	r.Began(t0, nil)
	r.Send(t0.Add(2*time.Second), 10, remote, 100, false, false)
	r.Started(10, 5, t0.Add(time.Second), "x.exe")
	r.Started(5, 1, t0, "parent.exe")
	res := query(r, 5, t0)
	if len(res.Sends) != 1 || res.Sends[0].PID != 10 || res.Sends[0].Image != "x.exe" || res.Sends[0].Via != "started by pid 5" {
		t.Errorf("sends = %+v", res.Sends)
	}
	if r.Status().Procs != 2 {
		t.Errorf("procs = %d", r.Status().Procs)
	}
}

// PID reuse: the process that had the number before isn't the member, and a
// child of that earlier process isn't the member's either.
func TestPIDReuse(t *testing.T) {
	r := New()
	r.Began(t0, nil)
	r.Started(10, 1, t0, "old.exe")
	r.Started(11, 10, t0.Add(time.Second), "oldchild.exe")
	r.Send(t0.Add(2*time.Second), 10, remote, 100, false, false)
	r.Exited(10, t0, t0.Add(3*time.Second))
	r.Send(t0.Add(4*time.Second), 11, remote, 100, false, false)
	newStart := t0.Add(time.Minute)
	r.Started(10, 1, newStart, "new.exe")
	r.Send(newStart.Add(time.Second), 10, remote, 7, false, false)
	res := r.Query(Query{Members: []Member{{PID: 10, Start: newStart}}, From: t0, To: t0.Add(time.Hour)})
	if len(res.Sends) != 1 || res.Sends[0].Bytes != 7 || res.Sends[0].Image != "new.exe" {
		t.Errorf("sends = %+v", res.Sends)
	}
}

// A member that had exited when asked (its start unknown): only a process
// the record knows the life of, in the time asked about, is it.
func TestMemberStartUnknown(t *testing.T) {
	r := New()
	r.Began(t0, nil)
	r.Started(10, 1, t0, "x.exe")
	r.Send(t0.Add(time.Second), 10, remote, 5, false, false)
	r.Exited(10, t0, t0.Add(2*time.Second))
	res := r.Query(Query{Members: []Member{{PID: 10}}, From: t0, To: t0.Add(time.Minute)})
	if len(res.Sends) != 1 {
		t.Errorf("sends = %+v", res.Sends)
	}
	res = r.Query(Query{Members: []Member{{PID: 10}}, From: t0.Add(time.Minute), To: t0.Add(2 * time.Minute)})
	if len(res.Sends) != 0 {
		t.Errorf("one that exited before the time asked about isn't it: %+v", res.Sends)
	}
}

func TestIgnoredAndLAN(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "127.97.98.97", "::1", "::ffff:127.0.0.1", "224.0.0.251", "ff02::fb", "255.255.255.255", "0.0.0.0"} {
		if !Ignored(netip.MustParseAddr(a)) {
			t.Errorf("%s should be ignored", a)
		}
	}
	for _, a := range []string{"192.168.89.1", "10.0.0.8", "172.16.4.1", "fe80::1", "fd00::1", "169.254.1.1"} {
		if Ignored(netip.MustParseAddr(a)) || !LocalNetwork(netip.MustParseAddr(a)) {
			t.Errorf("%s: a device on the local network", a)
		}
	}
	for _, a := range []string{"162.159.135.232", "2606:4700::1", "100.64.0.1"} {
		if Ignored(netip.MustParseAddr(a)) || LocalNetwork(netip.MustParseAddr(a)) {
			t.Errorf("%s: the internet", a)
		}
	}
	r := New()
	r.Began(t0, nil)
	r.Started(10, 1, t0, "x.exe")
	r.Send(t0.Add(time.Second), 10, netip.MustParseAddrPort("127.97.98.97:443"), 100, false, false)
	if res := query(r, 10, t0); len(res.Sends) != 0 {
		t.Errorf("loopback kept: %+v", res.Sends)
	}
}

func TestNames(t *testing.T) {
	r := New()
	r.Began(t0, nil)
	r.Started(10, 1, t0, "x.exe")
	r.Resolved(t0, 99, "other.example", []netip.Addr{remote.Addr()})
	r.Resolved(t0, 10, "discord.com", []netip.Addr{netip.MustParseAddr("::ffff:162.159.135.232")})
	r.Send(t0.Add(time.Second), 10, remote, 5, false, false)
	if res := query(r, 10, t0); len(res.Sends) != 1 || res.Sends[0].Name != "discord.com" || res.Sends[0].Where() != "discord.com (162.159.135.232:443)" {
		t.Errorf("its own lookup names it: %+v", res.Sends)
	}
	got := DNSAddrs("type:  5 discord.com;::ffff:162.159.135.232;2606:4700::6810:84e5;")
	if fmt.Sprint(got) != "[162.159.135.232 2606:4700::6810:84e5]" {
		t.Errorf("DNSAddrs = %v", got)
	}
}

func TestLapsesStopsAndForgetting(t *testing.T) {
	r := New()
	if st := r.Status(); st.Running || st.Why == "" {
		t.Errorf("a new record isn't running: %+v", st)
	}
	r.Began(t0, nil)
	r.Lost(t0.Add(time.Second), t0.Add(2*time.Second), "dropped")
	r.Lost(t0.Add(2*time.Second), t0.Add(3*time.Second), "dropped")
	r.Started(10, 1, t0, "x.exe")
	res := query(r, 10, t0)
	if len(res.Lapses) != 1 || !res.Lapses[0].To.Equal(t0.Add(3*time.Second)) || !res.Running {
		t.Errorf("lapses = %+v", res.Lapses)
	}
	r.Stopped(t0.Add(time.Minute), "the service stopped")
	if res := query(r, 10, t0); res.Running || res.Why != "the service stopped" {
		t.Errorf("stopped: %+v", res)
	}

	r = New()
	now := t0
	r.now = func() time.Time { return now }
	r.Began(t0, nil)
	r.Started(10, 1, t0, "x.exe")
	r.Send(t0.Add(time.Second), 10, remote, 5, false, false)
	r.Exited(10, t0, t0.Add(2*time.Second))
	now = t0.Add(keepExited + time.Hour)
	r.Prune()
	res = r.Query(Query{Members: []Member{{PID: 20, Start: t0}}, From: t0, To: now})
	if res.Forgot.IsZero() || r.Status().Procs != 0 {
		t.Errorf("a forgotten process must show: forgot %v procs %d", res.Forgot, r.Status().Procs)
	}
}
