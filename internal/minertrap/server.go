package minertrap

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Catch is a program that logged in to mine at the fake pool.
type Catch struct {
	Time   time.Time
	Client netip.AddrPort // the program's end of the connection
	Server netip.AddrPort // the fake pool's end
	TLS    bool
	SNI    string // the pool name it asked for in TLS (most miners send it)
	Login  Login
	// Names are the pool names looked up in the minutes before, oldest
	// first: the pool it wanted, when it didn't say. (Windows looks names up
	// for every program itself, so a lookup can't be tied to a program; and
	// XMRig, for one, names no server in TLS.)
	Names []string
}

// Pool is the pool it wanted, as best as ABA can tell, and whether that's
// sure (it said so) or a guess (the pool name looked up last before it
// connected: programs look a name up right before connecting to it).
func (c Catch) Pool() (string, bool) {
	if c.SNI != "" {
		return c.SNI, true
	}
	if len(c.Names) > 0 {
		return c.Names[len(c.Names)-1], false
	}
	return "", false
}

// How long the fake pool waits: for a program to say anything once
// connected, for a TLS handshake, for the wallet once it said hello, and how
// long it keeps the line of a caught program open. A caught miner is frozen
// in a moment; one that isn't (the response is "alert only") is given
// nothing to mine, and sits waiting until it gives up. Miners say nothing
// for minutes on end, so nothing here is short.
const (
	firstWait     = 10 * time.Minute
	handshakeWait = 30 * time.Second
	walletWait    = 15 * time.Second
	holdFor       = 30 * time.Minute
	maxConns      = 128
	recentFor     = 3 * time.Minute
)

// Trap is the fake pool and the DNS responder, listening on Addr.
type Trap struct {
	Addr    netip.Addr
	DNSPort int   // 53; 0 picks a free one (tests)
	Ports   []int // the pool's ports; a 0 picks a free one (tests)
	// OnCatch is told about each program that logs in to mine. The fake pool
	// holds that program's connection meanwhile, and answers it nothing.
	OnCatch func(Catch)
	// OnQuery, if set, hears about every DNS question answered.
	OnQuery func(Query)
	Logf    func(format string, a ...any)

	mu       sync.Mutex
	closers  []io.Closer
	conns    map[net.Conn]bool
	recent   []recentName
	dnsAt    string
	poolAt   []netip.AddrPort
	failed   []string
	stopped  bool
	certOnce sync.Once
	cert     *tls.Certificate
	certErr  error
}

type recentName struct {
	name string
	at   time.Time
}

// Status is what's listening.
type Status struct {
	DNS    string           // the DNS responder's address ("" if it isn't running)
	Pool   []netip.AddrPort // the fake pool's addresses
	Failed []string         // what couldn't listen, and why
}

func (t *Trap) logf(format string, a ...any) {
	if t.Logf != nil {
		t.Logf(format, a...)
	}
}

// Start opens every listener it can. It fails only if the DNS responder and
// every pool port failed: a port something else holds is skipped (logged in
// Status().Failed), and the rest still trap.
func (t *Trap) Start() error {
	t.mu.Lock()
	if t.conns == nil {
		t.conns = map[net.Conn]bool{}
	}
	t.mu.Unlock()
	sem := make(chan struct{}, maxConns)
	host := t.Addr.String()

	dnsPort := strconv.Itoa(t.DNSPort)
	if pc, err := net.ListenPacket("udp4", net.JoinHostPort(host, dnsPort)); err != nil {
		t.fail("DNS (udp " + dnsPort + "): " + err.Error())
	} else {
		at := pc.LocalAddr().String()
		t.keep(pc)
		go t.dnsUDP(pc)
		// The same port over TCP, which a resolver falls back to.
		_, p, _ := net.SplitHostPort(at)
		if l, err := net.Listen("tcp4", net.JoinHostPort(host, p)); err == nil {
			t.keep(l)
			go t.accept(l, sem, t.dnsTCP)
		}
		t.mu.Lock()
		t.dnsAt = at
		t.mu.Unlock()
	}
	for _, port := range t.Ports {
		l, err := net.Listen("tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			t.fail("port " + strconv.Itoa(port) + ": " + err.Error())
			continue
		}
		t.keep(l)
		t.mu.Lock()
		t.poolAt = append(t.poolAt, netip.MustParseAddrPort(l.Addr().String()))
		t.mu.Unlock()
		go t.accept(l, sem, t.serve)
	}
	st := t.Status()
	if st.DNS == "" && len(st.Pool) == 0 {
		t.Stop()
		return fmt.Errorf("nothing could listen on %s: %v", host, st.Failed)
	}
	return nil
}

func (t *Trap) fail(what string) {
	t.mu.Lock()
	t.failed = append(t.failed, what)
	t.mu.Unlock()
}

func (t *Trap) keep(c io.Closer) {
	t.mu.Lock()
	t.closers = append(t.closers, c)
	t.mu.Unlock()
}

// Status says what's listening.
func (t *Trap) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Status{DNS: t.dnsAt, Pool: append([]netip.AddrPort(nil), t.poolAt...), Failed: append([]string(nil), t.failed...)}
}

// Stop closes every listener and connection. It doesn't wait for OnCatch.
func (t *Trap) Stop() {
	t.mu.Lock()
	t.stopped = true
	cl := t.closers
	t.closers = nil
	conns := t.conns
	t.conns = map[net.Conn]bool{}
	t.dnsAt, t.poolAt = "", nil
	t.mu.Unlock()
	for _, c := range cl {
		c.Close()
	}
	for c := range conns {
		c.Close()
	}
}

func (t *Trap) isStopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopped
}

func (t *Trap) accept(l net.Listener, sem chan struct{}, serve func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			if t.isStopped() || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close() // that many open at once is no miner
			continue
		}
		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			c.Close()
			<-sem
			return
		}
		t.conns[c] = true
		t.mu.Unlock()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					t.logf("miner trap: PANIC serving %s: %v", c.RemoteAddr(), r)
				}
				t.mu.Lock()
				delete(t.conns, c)
				t.mu.Unlock()
				c.Close()
				<-sem
			}()
			serve(c)
		}()
	}
}

// ---- DNS ----

func (t *Trap) dnsUDP(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if t.isStopped() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		resp, q, err := Answer(buf[:n], t.Addr)
		if err != nil {
			continue
		}
		t.heard(q)
		pc.WriteTo(resp, from)
	}
}

func (t *Trap) dnsTCP(c net.Conn) {
	for i := 0; i < 16; i++ {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp, q, err := Answer(msg, t.Addr)
		if err != nil {
			return
		}
		t.heard(q)
		out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
		if _, err := c.Write(append(out, resp...)); err != nil {
			return
		}
	}
}

// heard notes a question, to say later which pool a plain connection wanted.
func (t *Trap) heard(q Query) {
	if t.OnQuery != nil {
		t.OnQuery(q)
	}
	if q.Pool == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	keep := t.recent[:0]
	for _, r := range t.recent {
		if now.Sub(r.at) < recentFor && r.name != q.Name {
			keep = append(keep, r)
		}
	}
	t.recent = append(keep, recentName{q.Name, now})
	if len(t.recent) > 32 {
		t.recent = t.recent[len(t.recent)-32:]
	}
}

func (t *Trap) recentNames() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for _, r := range t.recent {
		if time.Since(r.at) < recentFor {
			out = append(out, r.name)
		}
	}
	return out
}

// ---- the fake pool ----

// blockedPage is what a browser opening a pool's website gets, over plain
// HTTP (over HTTPS it first warns about the certificate, which is right: it
// isn't the pool's).
const blockedPage = "This is a crypto-mining pool's address. A Better Antivirus's miner trap is on, so on this PC it leads to a fake pool.\n" +
	"If you mine on purpose, turn the trap off: open a terminal as administrator and run  aba miners off\n"

func (t *Trap) serve(c net.Conn) {
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	local, _ := netip.ParseAddrPort(c.LocalAddr().String())
	catch := Catch{Client: ap, Server: local}
	c.SetDeadline(time.Now().Add(firstWait))
	br := bufio.NewReaderSize(c, 4096)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	var w io.Writer = c
	if first[0] == 0x16 { // a TLS handshake
		c.SetDeadline(time.Now().Add(handshakeWait))
		tc := tls.Server(&peeked{Conn: c, r: br}, &tls.Config{GetCertificate: t.certificate, MinVersion: tls.VersionTLS10})
		if err := tc.Handshake(); err != nil {
			t.logf("miner trap: TLS from %s on port %d didn't finish: %v", ap, local.Port(), err)
			return
		}
		catch.TLS, catch.SNI = true, clean(tc.ConnectionState().ServerName, 255)
		c.SetDeadline(time.Now().Add(firstWait))
		br, w = bufio.NewReaderSize(tc, 4096), tc
	}
	line, err := readLine(br)
	if err != nil && len(line) == 0 {
		return
	}
	line = bytes.TrimSpace(line)
	if looksHTTP(line) {
		fmt.Fprintf(w, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(blockedPage), blockedPage)
		t.logf("miner trap: a web request for %q on port %d (not a miner): %s", catch.SNI, local.Port(), clean(string(line), 120))
		return
	}
	login, id, ok := ParseMessage(line)
	if !ok {
		t.logf("miner trap: %s on port %d sent something that isn't a miner's login (%d bytes, starts %q)", ap, local.Port(), len(line), clean(string(line[:min(len(line), 40)]), 60))
		return
	}
	if login.Wallet == "" && (login.Method == "mining.subscribe" || login.Method == "mining.hello") {
		// It said hello; the wallet comes when it authorizes.
		w.Write(subscribeReply(id))
		c.SetDeadline(time.Now().Add(walletWait))
		for i := 0; i < 4 && login.Wallet == ""; i++ {
			next, err := readLine(br)
			if m, _, ok := ParseMessage(bytes.TrimSpace(next)); ok {
				login.Merge(m)
			}
			if err != nil {
				break
			}
		}
	}
	catch.Login, catch.Time, catch.Names = login, time.Now(), t.recentNames()
	if t.OnCatch != nil {
		t.OnCatch(catch)
	}
	// Hold the line, answering nothing: no work to do, no reason to go
	// elsewhere. (A frozen program holds it until it's let go or killed.)
	c.SetDeadline(time.Now().Add(holdFor))
	io.Copy(io.Discard, io.LimitReader(br, 1<<20))
}

// readLine reads one line of at most MaxLine bytes.
func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > MaxLine {
			return nil, errors.New("line too long")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return out, err
	}
}

func looksHTTP(line []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "CONNECT ", "DELETE ", "PATCH "} {
		if bytes.HasPrefix(line, []byte(m)) {
			return true
		}
	}
	return false
}

// peeked is a connection whose first bytes were already read into r.
type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

// certificate is the fake pool's: self-signed, made on this PC the first
// time a miner asks for TLS, and kept only in memory. Miners don't check
// whose a certificate is (they'd have to be told the pool's fingerprint).
func (t *Trap) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.certOnce.Do(func() { t.cert, t.certErr = selfSigned() })
	return t.cert, t.certErr
}

func selfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pool"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
