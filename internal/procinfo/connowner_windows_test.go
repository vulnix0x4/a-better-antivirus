package procinfo

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestConnOwner(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// From the listener's side: who is at the other end?
	client := netip.MustParseAddrPort(s.RemoteAddr().String())
	server := netip.MustParseAddrPort(s.LocalAddr().String())
	pid, err := ConnOwner(client, server)
	if err != nil || pid != uint32(os.Getpid()) {
		t.Errorf("owner %d, %v; want %d", pid, err, os.Getpid())
	}
	if pid, _ := ConnOwner(server, netip.MustParseAddrPort("127.0.0.1:1")); pid != 0 {
		t.Errorf("found %d for a connection that doesn't exist", pid)
	}
}
