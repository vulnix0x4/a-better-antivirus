package minertrap

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPoolList(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Pools {
		if p != strings.ToLower(strings.TrimSpace(p)) || strings.HasPrefix(p, ".") || strings.HasSuffix(p, ".") || !strings.Contains(p, ".") {
			t.Errorf("pool %q: write it lower case, with no dots at either end", p)
		}
		if seen[p] {
			t.Errorf("pool %q listed twice", p)
		}
		seen[p] = true
		for _, q := range Pools {
			if q != p && strings.HasSuffix(p, "."+q) {
				t.Errorf("pool %q is already covered by %q", p, q)
			}
		}
	}
	for _, must := range []string{"hashvault.pro", "hashvault.sh", "supportxmr.com", "moneroocean.stream", "nanopool.org", "c3pool.com",
		"2miners.com", "herominers.com", "unmineable.com", "xmrpool.eu", "monerohash.com", "minexmr.com", "xmr.f2pool.com", "xmr.kryptex.network"} {
		if !seen[must] {
			t.Errorf("%s is missing", must)
		}
	}
	if len(Namespaces()) != 2*len(Pools) {
		t.Errorf("namespaces: %d for %d pools", len(Namespaces()), len(Pools))
	}
}

func TestMatch(t *testing.T) {
	for name, want := range map[string]string{
		"pool.hashvault.pro":              "hashvault.pro",
		"POOL.HashVault.Pro.":             "hashvault.pro",
		"hashvault.pro":                   "hashvault.pro",
		"gulf.moneroocean.stream":         "moneroocean.stream",
		"xmr-eu1.nanopool.org":            "nanopool.org",
		"xmr.f2pool.com":                  "xmr.f2pool.com",
		"randomxmonero.auto.nicehash.com": "auto.nicehash.com",
		// Never anything else.
		"f2pool.com":             "",
		"btc.f2pool.com":         "",
		"nicehash.com":           "",
		"www.nicehash.com":       "",
		"nothashvault.pro":       "",
		"hashvault.pro.evil.com": "",
		"supportxmr.co":          "",
		"github.com":             "",
		"xmrig.com":              "",
		"microsoft.com":          "",
		"":                       "",
		".":                      "",
	} {
		got, ok := Match(name)
		if got != want || ok != (want != "") {
			t.Errorf("Match(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
}

// query builds a DNS question.
func query(id uint16, name string, typ uint16) []byte {
	b := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(b, typ), dnsClassIN)
}

func TestAnswer(t *testing.T) {
	ip := netip.MustParseAddr(Addr)
	resp, q, err := Answer(query(0x1234, "pool.hashvault.pro", dnsTypeA), ip)
	if err != nil || q.Pool != "hashvault.pro" || q.Name != "pool.hashvault.pro" {
		t.Fatalf("answer: %v %+v", err, q)
	}
	if resp[0] != 0x12 || resp[1] != 0x34 || resp[2]&0x80 == 0 || resp[3]&0x0f != 0 || binary.BigEndian.Uint16(resp[6:]) != 1 {
		t.Fatalf("bad header % x", resp[:12])
	}
	if got := resp[len(resp)-4:]; !bytes.Equal(got, ip.AsSlice()) {
		t.Errorf("answered %v", got)
	}
	// IPv6: the name exists, with no IPv6 address.
	resp, _, _ = Answer(query(1, "pool.hashvault.pro", dnsTypeAAAA), ip)
	if resp[3]&0x0f != 0 || binary.BigEndian.Uint16(resp[6:]) != 0 {
		t.Errorf("AAAA: % x", resp[:12])
	}
	// Anything else is refused, never answered.
	for _, n := range []string{"example.com", "hashvault.pro.example.com", "a.b"} {
		resp, q, _ := Answer(query(2, n, dnsTypeA), ip)
		if resp[3]&0x0f != rcodeRefused || binary.BigEndian.Uint16(resp[6:]) != 0 || q.Pool != "" {
			t.Errorf("%s: % x", n, resp[:12])
		}
	}
	// A reply is never answered (no loops), and garbage gets no answer or an error code.
	r := query(3, "pool.hashvault.pro", dnsTypeA)
	r[2] |= 0x80
	if resp, _, err := Answer(r, ip); err == nil || resp != nil {
		t.Error("answered a reply")
	}
	if _, _, err := Answer([]byte{1, 2, 3}, ip); err == nil {
		t.Error("answered a scrap")
	}
	ptr := append(query(4, "a", dnsTypeA)[:12], 0xC0, 0x0C, 0, 1, 0, 1)
	if resp, _, _ := Answer(ptr, ip); resp[3]&0x0f != rcodeFormErr {
		t.Errorf("a compressed question: % x", resp)
	}
}

func FuzzAnswer(f *testing.F) {
	f.Add(query(1, "pool.hashvault.pro", dnsTypeA))
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 63})
	f.Fuzz(func(t *testing.T, b []byte) {
		resp, q, err := Answer(b, AddrIP)
		if err == nil && len(resp) < 12 {
			t.Fatal("short reply")
		}
		if q.Pool != "" {
			if _, ok := Match(q.Name); !ok {
				t.Fatalf("answered %q", q.Name)
			}
		}
	})
}

func TestAnswerGarbage(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.IntN(80))
		for j := range b {
			b[j] = byte(r.IntN(256))
		}
		if i%2 == 0 && len(b) > 12 {
			copy(b, query(1, "pool.hashvault.pro", 1)) // a real start, then noise
		}
		resp, q, _ := Answer(b, AddrIP)
		if q.Pool != "" {
			if _, ok := Match(q.Name); !ok {
				t.Fatalf("answered %q", q.Name)
			}
		}
		_ = resp
	}
}

const xmrigLogin = `{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"43iNancbmDEMOkv43M","pass":"RealBigTonka#","agent":"XMRig/6.24.0 (Windows NT 10.0; Win64; x64) libuv/1.51.0 msvc/2022","rigid":"","algo":["cn/1","rx/0","rx/wow","rx/arq"]}}`

func TestParseMessage(t *testing.T) {
	l, id, ok := ParseMessage([]byte(xmrigLogin))
	if !ok || string(id) != "1" || l.Method != "login" || l.Wallet != "43iNancbmDEMOkv43M" || l.Pass != "RealBigTonka#" ||
		!strings.HasPrefix(l.Agent, "XMRig/6.24.0") || len(l.Algo) != 4 {
		t.Fatalf("%+v", l)
	}
	l, _, ok = ParseMessage([]byte(`{"id":2,"method":"mining.authorize","params":["RVNwallet.rig1","x"]}`))
	if !ok || l.Wallet != "RVNwallet.rig1" || l.Pass != "x" {
		t.Errorf("authorize: %+v", l)
	}
	l, _, ok = ParseMessage([]byte(`{"id":1,"method":"mining.subscribe","params":["SRBMiner-MULTI/2.4.0","EthereumStratum/1.0.0"]}`))
	if !ok || l.Agent != "SRBMiner-MULTI/2.4.0" || l.Wallet != "" {
		t.Errorf("subscribe: %+v", l)
	}
	l, _, ok = ParseMessage([]byte(`{"id":1,"method":"eth_submitLogin","worker":"w1","params":["0xabc","x"]}`))
	if !ok || l.Wallet != "0xabc" || l.Rig != "w1" {
		t.Errorf("eth: %+v", l)
	}
	// Not a miner.
	for _, s := range []string{``, `{}`, `[]`, `null`, `{"method":"getjob"}`, `{"method":"eth_call","params":[]}`, `GET / HTTP/1.1`,
		`{"method":"login"`, `{"jsonrpc":"2.0","method":"initialize"}`, strings.Repeat("{", 5000)} {
		if _, _, ok := ParseMessage([]byte(s)); ok {
			t.Errorf("%q taken for a miner", s)
		}
	}
	// Wrong types where strings belong: still a miner, nothing made up.
	if l, _, ok := ParseMessage([]byte(`{"method":"login","params":{"login":42,"agent":["x"]}}`)); !ok || l.Wallet != "" || l.Agent != "" {
		t.Errorf("odd types: %v %+v", ok, l)
	}
	if l, _, ok := ParseMessage([]byte(`{"method":"mining.authorize","params":[1,2]}`)); !ok || l.Wallet != "" {
		t.Errorf("odd params: %v %+v", ok, l)
	}
	// Huge: refused. Long fields: cut. Control characters and text-reordering ones: dropped.
	if _, _, ok := ParseMessage([]byte(`{"method":"login","params":{"login":"` + strings.Repeat("a", MaxLine) + `"}}`)); ok {
		t.Error("a huge message was taken")
	}
	l, _, _ = ParseMessage([]byte(`{"method":"login","params":{"login":"` + strings.Repeat("w", 1000) + `","agent":"evil\u001b[2J‮agent\nline"}}`))
	if len(l.Wallet) > 210 || strings.ContainsAny(l.Agent, "\x1b\n‮") || l.Agent != "evil[2Jagentline" {
		t.Errorf("not cleaned: %d %q", len(l.Wallet), l.Agent)
	}
}

// startTrap runs a trap on 127.0.0.1 with free ports.
func startTrap(t *testing.T) (*Trap, chan Catch) {
	t.Helper()
	caught := make(chan Catch, 16)
	tr := &Trap{Addr: netip.MustParseAddr("127.0.0.1"), Ports: []int{0}, OnCatch: func(c Catch) { caught <- c }, Logf: t.Logf}
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.Stop)
	return tr, caught
}

func dial(t *testing.T, tr *Trap) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", tr.Status().Pool[0].String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func wait(t *testing.T, caught chan Catch) Catch {
	t.Helper()
	select {
	case c := <-caught:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("not caught")
	}
	return Catch{}
}

func TestTrapPlain(t *testing.T) {
	tr, caught := startTrap(t)
	c := dial(t, tr)
	fmt.Fprint(c, xmrigLogin+"\n")
	got := wait(t, caught)
	if got.Login.Wallet != "43iNancbmDEMOkv43M" || got.TLS || got.Client.String() != c.LocalAddr().String() || got.Server.String() != c.RemoteAddr().String() {
		t.Errorf("%+v", got)
	}
	// It's held, and told nothing: no job to mine.
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 10)); n != 0 || !isTimeout(err) {
		t.Errorf("the miner was answered (%d, %v)", n, err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestTrapTLS(t *testing.T) {
	tr, caught := startTrap(t)
	raw := dial(t, tr)
	c := tls.Client(raw, &tls.Config{ServerName: "pool.hashvault.pro", InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, xmrigLogin+"\n")
	got := wait(t, caught)
	if !got.TLS || got.SNI != "pool.hashvault.pro" || got.Login.Agent == "" {
		t.Errorf("%+v", got)
	}
	if p, sure := got.Pool(); p != "pool.hashvault.pro" || !sure {
		t.Errorf("pool %q %v", p, sure)
	}
}

func TestTrapSubscribeThenAuthorize(t *testing.T) {
	tr, caught := startTrap(t)
	c := dial(t, tr)
	fmt.Fprint(c, `{"id":1,"method":"mining.subscribe","params":["T-Rex/0.26.8"]}`+"\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, `"id":1`) || json.Valid([]byte(line)) == false {
		t.Fatalf("subscribe reply %q %v", line, err)
	}
	fmt.Fprint(c, `{"id":2,"method":"mining.authorize","params":["RVN123.w","x"]}`+"\n")
	got := wait(t, caught)
	if got.Login.Wallet != "RVN123.w" || got.Login.Agent != "T-Rex/0.26.8" {
		t.Errorf("%+v", got.Login)
	}
}

func TestTrapNotMiners(t *testing.T) {
	tr, caught := startTrap(t)
	// A browser opening the pool's website: told why, never caught.
	c := dial(t, tr)
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: supportxmr.com\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(b), "HTTP/1.1 403") || !strings.Contains(string(b), "aba miners off") {
		t.Errorf("web page: %q", b)
	}
	// Garbage, an endless line, a client that says nothing then leaves.
	g := dial(t, tr)
	g.Write([]byte{0, 1, 2, 3, '\n'})
	io.ReadAll(g)
	h := dial(t, tr)
	go h.Write(bytes.Repeat([]byte("x"), 4*MaxLine))
	h.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(h); err != nil && isTimeout(err) {
		t.Error("an endless line wasn't cut off")
	}
	q := dial(t, tr)
	q.Close()
	select {
	case c := <-caught:
		t.Errorf("caught %+v", c)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestTrapManyConnections(t *testing.T) {
	tr, caught := startTrap(t)
	// Far more than it holds at once: the extra ones are turned away, and the
	// trap still works after.
	var conns []net.Conn
	for i := 0; i < maxConns+40; i++ {
		c, err := net.Dial("tcp", tr.Status().Pool[0].String())
		if err != nil {
			break
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	c := dial(t, tr)
	fmt.Fprint(c, xmrigLogin+"\n")
	wait(t, caught)
}

func TestTrapDNSAndRecentNames(t *testing.T) {
	tr := &Trap{Addr: netip.MustParseAddr("127.0.0.1"), Ports: []int{0}, DNSPort: 0}
	var mu sync.Mutex
	var heard []Query
	tr.OnQuery = func(q Query) { mu.Lock(); heard = append(heard, q); mu.Unlock() }
	caught := make(chan Catch, 1)
	tr.OnCatch = func(c Catch) { caught <- c }
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	st := tr.Status()
	if st.DNS == "" {
		t.Fatalf("no DNS: %v", st.Failed)
	}
	u, err := net.Dial("udp", st.DNS)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write(query(7, "gulf.moneroocean.stream", dnsTypeA))
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	if err != nil || !bytes.Equal(buf[n-4:n], []byte{127, 0, 0, 1}) {
		t.Fatalf("dns: % x %v", buf[:n], err)
	}
	// Over TCP too.
	tc, err := net.Dial("tcp", st.DNS)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	q := query(8, "example.org", dnsTypeA)
	tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	var ln [2]byte
	io.ReadFull(tc, ln[:])
	resp := make([]byte, binary.BigEndian.Uint16(ln[:]))
	if _, err := io.ReadFull(tc, resp); err != nil || resp[3]&0x0f != rcodeRefused {
		t.Errorf("tcp dns: % x %v", resp, err)
	}
	// A plain login right after: the pool it looked up is the one it wanted.
	c, err := net.Dial("tcp", st.Pool[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, xmrigLogin+"\n")
	got := wait(t, caught)
	if p, sure := got.Pool(); p != "gulf.moneroocean.stream" || sure {
		t.Errorf("pool %q %v (%v)", p, sure, got.Names)
	}
	mu.Lock()
	if len(heard) != 2 {
		t.Errorf("heard %+v", heard)
	}
	mu.Unlock()
	// Two pools looked up: the last one before it connected is the likely one.
	u.Write(query(9, "pool.hashvault.pro", dnsTypeA))
	u.Read(buf)
	c2, err := net.Dial("tcp", st.Pool[0].String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	fmt.Fprint(c2, xmrigLogin+"\n")
	got = wait(t, caught)
	if p, _ := got.Pool(); p != "pool.hashvault.pro" || len(got.Names) != 2 {
		t.Errorf("pool %q (%v)", p, got.Names)
	}
}

func TestTrapStop(t *testing.T) {
	tr, _ := startTrap(t)
	c := dial(t, tr)
	addr := tr.Status().Pool[0].String()
	tr.Stop()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("an open connection survived Stop: %v", err)
	}
	if c2, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c2.Close()
		t.Error("still listening after Stop")
	}
	tr.Stop() // twice is fine
}

func TestTrapPortTaken(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	taken := l.Addr().(*net.TCPAddr).Port
	tr := &Trap{Addr: netip.MustParseAddr("127.0.0.1"), Ports: []int{taken, 0}, DNSPort: 0}
	if err := tr.Start(); err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	st := tr.Status()
	if len(st.Pool) != 1 || len(st.Failed) != 1 {
		t.Errorf("%+v", st)
	}
}
