package origin

import (
	"encoding/binary"
	"unicode/utf16"
)

// bplistStrings returns the strings in a binary property list whose top
// object is a string or an array of strings (macOS's "where from" attribute
// is such a list: the download address, then the page it came from). Anything
// else, or anything malformed, gives nil: this reads what another program
// may have written, so every offset is checked.
func bplistStrings(b []byte) []string {
	if len(b) < 8+32 || string(b[:8]) != "bplist00" {
		return nil
	}
	t := b[len(b)-32:]
	offSize, refSize := int(t[6]), int(t[7])
	num, top, table := binary.BigEndian.Uint64(t[8:]), binary.BigEndian.Uint64(t[16:]), binary.BigEndian.Uint64(t[24:])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || num == 0 || num > 1024 || top >= num ||
		table >= uint64(len(b)) || table+num*uint64(offSize) > uint64(len(b)-32) {
		return nil
	}
	be := func(p []byte) uint64 {
		var v uint64
		for _, c := range p {
			v = v<<8 | uint64(c)
		}
		return v
	}
	offset := func(obj uint64) (int, bool) {
		if obj >= num {
			return 0, false
		}
		at := table + obj*uint64(offSize)
		o := be(b[at : at+uint64(offSize)])
		if o < 8 || o >= table {
			return 0, false
		}
		return int(o), true
	}
	// count reads an object's length: in the marker, or in an int after it.
	count := func(at int) (n, start int, ok bool) {
		n, start = int(b[at]&0x0f), at+1
		if n != 0x0f {
			return n, start, true
		}
		if start >= len(b) || b[start]>>4 != 0x1 {
			return 0, 0, false
		}
		w := 1 << (b[start] & 0x0f)
		if w > 8 || start+1+w > len(b) {
			return 0, 0, false
		}
		v := be(b[start+1 : start+1+w])
		if v > uint64(len(b)) {
			return 0, 0, false
		}
		return int(v), start + 1 + w, true
	}
	str := func(obj uint64) (string, bool) {
		at, ok := offset(obj)
		if !ok {
			return "", false
		}
		n, s, ok := count(at)
		if !ok {
			return "", false
		}
		switch b[at] >> 4 {
		case 0x5: // ASCII
			if s+n > len(b) {
				return "", false
			}
			return string(b[s : s+n]), true
		case 0x6: // UTF-16 big-endian, n code units
			if s+2*n > len(b) {
				return "", false
			}
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.BigEndian.Uint16(b[s+2*i:])
			}
			return string(utf16.Decode(u)), true
		}
		return "", false
	}
	if s, ok := str(top); ok {
		return []string{s}
	}
	at, ok := offset(top)
	if !ok || b[at]>>4 != 0xA {
		return nil
	}
	n, s, ok := count(at)
	if !ok || s+n*refSize > len(b) {
		return nil
	}
	var out []string
	for i := 0; i < n; i++ {
		if v, ok := str(be(b[s+i*refSize : s+(i+1)*refSize])); ok {
			out = append(out, v)
		}
	}
	return out
}
