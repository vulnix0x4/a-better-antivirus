package netrec

// On Windows the record comes from Windows' own event tracing, no driver:
// one private real-time session with three of Windows' providers, each
// filtered (by Windows, before anything is written) to the few events used:
//
//   - Microsoft-Windows-Kernel-Network: a TCP connection made, TCP or UDP
//     data sent (which process, to where, how many bytes). Not what's
//     received: that's most of the traffic, and none of it leaves.
//   - Microsoft-Windows-Kernel-Process: a process started (and by which
//     process) or exited, so what a program started is found, and a number
//     reused by another process isn't mixed up with it.
//   - Microsoft-Windows-DNS-Client: the answers to name lookups, to name
//     the addresses ("discord.com", not 162.159.135.232).

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/etw"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// SessionName is the name of ABA's trace session (logman query -ets lists it).
const SessionName = "ABA Network Record"

var (
	kernelNetwork = windows.GUID{Data1: 0x7DD42A49, Data2: 0x5329, Data3: 0x4832, Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}}
	kernelProcess = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B, Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}
	dnsClient     = windows.GUID{Data1: 0x1C95126E, Data2: 0x7EEA, Data3: 0x49A9, Data4: [8]byte{0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}}
)

// The events used.
const (
	evTCPSend4    = 10
	evTCPConnect4 = 12
	evTCPSend6    = 26
	evTCPConnect6 = 28
	evUDPSend4    = 42
	evUDPSend6    = 58
	evProcStart   = 1
	evProcStop    = 2
	evDNSDone     = 3008
)

var providers = []etw.Provider{
	{GUID: kernelNetwork, Level: 5, Keywords: 0x30, // IPv4, IPv6
		EventIDs: []uint16{evTCPSend4, evTCPConnect4, evTCPSend6, evTCPConnect6, evUDPSend4, evUDPSend6}},
	{GUID: kernelProcess, Level: 5, Keywords: 0x10, // processes
		EventIDs: []uint16{evProcStart, evProcStop}},
	{GUID: dnsClient, Level: 5, EventIDs: []uint16{evDNSDone}},
}

// watcher is the running session and what it has seen.
type watcher struct {
	s    *etw.Session
	r    *Record
	self uint32
	// last is the time of the latest event read (unix nanoseconds).
	last atomic.Int64
	// mark is the port of the loopback send that shows the session has
	// caught up (see catchUp); seen is set when it's read.
	markPort atomic.Uint32
	seen     atomic.Bool
}

// Watch keeps r from Windows' event tracing until ctx is done, or the
// session fails. r says, all along, whether it's running.
func Watch(ctx context.Context, r *Record, logf func(string, ...any)) error {
	s, err := etw.Start(SessionName, providers)
	if err != nil {
		r.Stopped(time.Now(), "it couldn't start: "+err.Error())
		return err
	}
	w := &watcher{s: s, r: r, self: uint32(os.Getpid())}
	s.OnEvent = w.event
	s.OnLost = func(at time.Time, why string) { r.Lost(at.Add(-2*time.Second), at, why) }
	began := time.Now()
	// The processes already running, so their children and their sends are
	// placed (the session is on already: one starting now is heard either
	// way, and Started takes it once).
	if snap, err := procinfo.Snapshot(); err == nil {
		for _, e := range snap {
			if e.CreateTime != 0 {
				r.Started(e.PID, e.PPID, etw.FileTime(e.CreateTime), e.Exe)
			}
		}
	}
	done := make(chan error, 1)
	go func() { done <- s.Read() }()
	r.Began(began, w.catchUp)
	logf("network record: on (Windows event tracing)")

	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	prune := time.NewTicker(10 * time.Minute)
	defer prune.Stop()
	var lostEv, lostBuf uint32
	lastPoll := began
	for {
		select {
		case <-ctx.Done():
			s.Stop()
			<-done
			r.Stopped(time.Now(), "the service stopped")
			return nil
		case err := <-done:
			if err == nil {
				err = fmt.Errorf("Windows stopped it")
			}
			r.Stopped(time.Now(), err.Error())
			etw.StopByName(SessionName)
			return err
		case now := <-tick.C:
			ev, buf, err := s.Losses()
			if err == nil && (ev > lostEv || buf > lostBuf) {
				r.Lost(lastPoll.Add(-2*time.Second), now, fmt.Sprintf("Windows dropped %d of its reports (it was too busy)", (ev-lostEv)+(buf-lostBuf)))
				logf("network record: Windows dropped %d events, %d buffers", ev-lostEv, buf-lostBuf)
				lostEv, lostBuf = ev, buf
			}
			lastPoll = now
		case <-prune.C:
			r.Prune()
		}
	}
}

// catchUp makes sure what happened up to now has been read: it sends a
// datagram to itself (on loopback, so nothing leaves, and the record doesn't
// keep it), has Windows hand over what it has, and waits to read that send.
func (w *watcher) catchUp(timeout time.Duration) bool {
	mark := time.Now()
	w.seen.Store(false)
	if c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err == nil {
		port := c.LocalAddr().(*net.UDPAddr).Port
		w.markPort.Store(uint32(port))
		c.WriteToUDP([]byte("aba"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		defer c.Close()
	}
	defer w.markPort.Store(0)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		w.s.Flush()
		// Its own send read, or (should Windows not report sends to itself)
		// anything that happened after it asked.
		if w.seen.Load() || (time.Since(mark) > time.Second && w.last.Load() >= mark.UnixNano()) {
			// Events come in buffers, one per processor: one more round
			// for the others.
			time.Sleep(100 * time.Millisecond)
			w.s.Flush()
			time.Sleep(100 * time.Millisecond)
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// events counts the events read (for the cost test).
var events atomic.Int64

func (w *watcher) event(e *etw.EventRecord) {
	events.Add(1)
	at := e.Time()
	if n := at.UnixNano(); n > w.last.Load() {
		w.last.Store(n)
	}
	d := e.Data()
	switch e.Header.ProviderID {
	case kernelNetwork:
		w.network(at, e.Header.ID, d)
	case kernelProcess:
		switch e.Header.ID {
		case evProcStart:
			if pid, ppid, start, name, ok := procStart(at, e.Header.Version, d); ok {
				w.r.Started(pid, ppid, start, name)
			}
		case evProcStop:
			if pid, start, exit, ok := procStop(at, d); ok {
				w.r.Exited(pid, start, exit)
			}
		}
	case dnsClient:
		if e.Header.ID != evDNSDone {
			return
		}
		name, off := utf16z(d, 0)
		if off < 0 || off+16 > len(d) {
			return
		}
		status := le32(d, off+12)
		results, _ := utf16z(d, off+16)
		if status != 0 || name == "" {
			return
		}
		if addrs := DNSAddrs(results); len(addrs) > 0 {
			w.r.Resolved(at, e.Header.ProcessID, strings.TrimSuffix(strings.ToLower(name), "."), addrs)
		}
	}
}

func (w *watcher) network(at time.Time, id uint16, d []byte) {
	var v6, conn, udp bool
	switch id {
	case evTCPSend4:
	case evTCPConnect4:
		conn = true
	case evUDPSend4:
		udp = true
	case evTCPSend6:
		v6 = true
	case evTCPConnect6:
		v6, conn = true, true
	case evUDPSend6:
		v6, udp = true, true
	default:
		return
	}
	n := 20
	if v6 {
		n = 44
	}
	if len(d) < n {
		return
	}
	pid, size := le32(d, 0), le32(d, 4)
	var addr netip.Addr
	var port uint16
	if v6 {
		addr = netip.AddrFrom16([16]byte(d[8:24]))
		port = binary.BigEndian.Uint16(d[40:42])
	} else {
		addr = netip.AddrFrom4([4]byte(d[8:12]))
		port = binary.BigEndian.Uint16(d[16:18])
	}
	if pid == w.self && udp && addr.Unmap().IsLoopback() {
		if mp := w.markPort.Load(); mp != 0 && uint32(port) == mp {
			w.seen.Store(true)
		}
		return
	}
	if conn {
		size = 0
	}
	w.r.Send(at, pid, netip.AddrPortFrom(addr.Unmap(), port), int(size), conn, udp)
}

// procStart reads a process start event. Since Windows 10 it carries the
// process's sequence number after its ID (and its parent's after the
// parent's ID), and its elevation and integrity level before its image name;
// older versions don't. The start time tells the layouts apart: it has to be
// a moment before the event.
func procStart(at time.Time, version uint8, d []byte) (pid, ppid uint32, start time.Time, image string, ok bool) {
	if len(d) >= 52 && plausible(at, d, 12) {
		// ProcessID, ProcessSequenceNumber, CreateTime, ParentProcessID,
		// ParentProcessSequenceNumber, SessionID, Flags, elevation type,
		// elevated, MandatoryLabel (a SID), ImageName…
		img := -1
		if n := int(d[49]); 48+8+4*n <= len(d) {
			img = 48 + 8 + 4*n
		}
		if img > 0 {
			image, _ = utf16z(d, img)
		}
		return le32(d, 0), le32(d, 20), etw.FileTime(int64(le64(d, 12))), baseName(image), true
	}
	if len(d) >= 20 && plausible(at, d, 4) {
		// ProcessID, CreateTime, ParentProcessID, SessionID, [Flags,] ImageName
		img := 20
		if version >= 1 {
			img = 24
		}
		image, _ = utf16z(d, img)
		return le32(d, 0), le32(d, 12), etw.FileTime(int64(le64(d, 4))), baseName(image), true
	}
	return 0, 0, time.Time{}, "", false
}

// procStop reads a process stop event (the same two layouts).
func procStop(at time.Time, d []byte) (pid uint32, start, exit time.Time, ok bool) {
	switch {
	case len(d) >= 28 && plausible(at, d, 12):
		return le32(d, 0), etw.FileTime(int64(le64(d, 12))), etw.FileTime(int64(le64(d, 20))), true
	case len(d) >= 20 && plausible(at, d, 4):
		return le32(d, 0), etw.FileTime(int64(le64(d, 4))), etw.FileTime(int64(le64(d, 12))), true
	}
	return 0, time.Time{}, time.Time{}, false
}

// plausible: the FILETIME at d[i:] is a moment in the 30 years before at.
func plausible(at time.Time, d []byte, i int) bool {
	t := etw.FileTime(int64(le64(d, i)))
	return !t.IsZero() && !t.After(at.Add(5*time.Second)) && t.After(at.AddDate(-30, 0, 0))
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func le32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
func le64(b []byte, i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }

// utf16z reads a zero-terminated UTF-16 string at b[i:], and says where what
// follows it starts (-1 if it isn't terminated).
func utf16z(b []byte, i int) (string, int) {
	var u []uint16
	for j := i; j+1 < len(b); j += 2 {
		c := binary.LittleEndian.Uint16(b[j:])
		if c == 0 {
			return string(utf16.Decode(u)), j + 2
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u)), -1
}
