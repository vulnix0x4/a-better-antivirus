package minertrap

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
)

// The DNS responder only ever answers for the pool names: Windows sends it
// nothing else (see nrpt_windows.go), and anything else it's asked it
// refuses. Its whole job is "pool name -> Addr", so it's a few dozen lines
// rather than a DNS library.

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
	dnsTypeANY  = 255
	dnsClassIN  = 1

	rcodeFormErr = 1
	rcodeNotImp  = 4
	rcodeRefused = 5

	// TTL of an answer: short, so that switching the trap off is felt at once
	// even by a program that keeps its own cache of names.
	answerTTL = 30
)

var errNotQuery = errors.New("not a DNS query")

// Query is what a DNS question asked, for the trap's records.
type Query struct {
	Name string // lower case, no final dot
	Type uint16
	Pool string // the pool it's a name of ("" if none)
}

// Answer builds the reply to one DNS message q, answering pool names with ip.
// It returns errNotQuery (and no reply) for anything that isn't a question:
// replies, and messages too short to be one.
func Answer(q []byte, ip netip.Addr) ([]byte, Query, error) {
	var out Query
	if len(q) < 12 {
		return nil, out, errNotQuery
	}
	flags := binary.BigEndian.Uint16(q[2:])
	if flags&0x8000 != 0 {
		return nil, out, errNotQuery // a reply: never answer those (no loops)
	}
	opcode := flags & 0x7800
	reply := func(rcode uint16, question []byte, answer []byte) []byte {
		b := make([]byte, 12, 12+len(question)+len(answer))
		copy(b, q[:2])
		f := 0x8000 | opcode | 0x0400 | flags&0x0100 | rcode // QR, AA, RD as asked
		binary.BigEndian.PutUint16(b[2:], f)
		if question != nil {
			binary.BigEndian.PutUint16(b[4:], 1)
		}
		if answer != nil {
			binary.BigEndian.PutUint16(b[6:], 1)
		}
		b = append(b, question...)
		return append(b, answer...)
	}
	if opcode != 0 {
		return reply(rcodeNotImp, nil, nil), out, nil
	}
	if binary.BigEndian.Uint16(q[4:]) != 1 {
		return reply(rcodeFormErr, nil, nil), out, nil
	}
	name, end, ok := readName(q, 12)
	if !ok || end+4 > len(q) {
		return reply(rcodeFormErr, nil, nil), out, nil
	}
	question := q[12 : end+4]
	out.Name = name
	out.Type = binary.BigEndian.Uint16(q[end:])
	class := binary.BigEndian.Uint16(q[end+2:])
	pool, isPool := Match(name)
	if !isPool || class != dnsClassIN {
		return reply(rcodeRefused, question, nil), out, nil
	}
	out.Pool = pool
	var answer []byte
	switch {
	case ip.Is4() && (out.Type == dnsTypeA || out.Type == dnsTypeANY):
		answer = rr(dnsTypeA, ip.AsSlice())
	case ip.Is6() && !ip.Is4In6() && (out.Type == dnsTypeAAAA || out.Type == dnsTypeANY):
		answer = rr(dnsTypeAAAA, ip.AsSlice())
	}
	// Any other type: the name exists, with no record of that type ("NODATA"),
	// so a program asking for IPv6 first goes on to ask for IPv4.
	return reply(0, question, answer), out, nil
}

// rr is one answer record for the question's name (a pointer to offset 12).
func rr(typ uint16, data []byte) []byte {
	b := []byte{0xC0, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], typ)
	binary.BigEndian.PutUint16(b[4:], dnsClassIN)
	binary.BigEndian.PutUint32(b[6:], answerTTL)
	binary.BigEndian.PutUint16(b[10:], uint16(len(data)))
	return append(b, data...)
}

// readName reads the uncompressed name at off (questions are never
// compressed) and returns it and where it ends.
func readName(b []byte, off int) (string, int, bool) {
	var labels []string
	total := 0
	for {
		if off >= len(b) {
			return "", 0, false
		}
		n := int(b[off])
		off++
		if n == 0 {
			break
		}
		if n > 63 || off+n > len(b) {
			return "", 0, false // a compression pointer, or cut short
		}
		total += n + 1
		if total > 255 {
			return "", 0, false
		}
		labels = append(labels, strings.ToLower(string(b[off:off+n])))
		off += n
	}
	return strings.Join(labels, "."), off, true
}
