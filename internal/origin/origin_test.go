package origin

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// encodeBplist writes strs as a binary property list: an array of strings,
// or a single string when there's one and single is set.
func encodeBplist(strs []string, single bool) []byte {
	b := []byte("bplist00")
	var offs []int
	var objs [][]byte
	marker := func(kind byte, n int) []byte {
		if n < 15 {
			return []byte{kind<<4 | byte(n)}
		}
		return []byte{kind<<4 | 0x0f, 0x11, byte(n >> 8), byte(n)}
	}
	for _, s := range strs {
		ascii := true
		for _, r := range s {
			if r > 127 {
				ascii = false
			}
		}
		if ascii {
			objs = append(objs, append(marker(0x5, len(s)), s...))
			continue
		}
		u := utf16.Encode([]rune(s))
		o := marker(0x6, len(u))
		for _, c := range u {
			o = binary.BigEndian.AppendUint16(o, c)
		}
		objs = append(objs, o)
	}
	top := 0
	if !single {
		arr := marker(0xA, len(strs))
		for i := range strs {
			arr = append(arr, byte(i+1))
		}
		objs = append([][]byte{arr}, objs...)
	}
	for _, o := range objs {
		offs = append(offs, len(b))
		b = append(b, o...)
	}
	table := len(b)
	for _, o := range offs {
		b = binary.BigEndian.AppendUint16(b, uint16(o))
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 2, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(objs)))
	binary.BigEndian.PutUint64(trailer[16:], uint64(top))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	return append(b, trailer...)
}

func TestBplistStrings(t *testing.T) {
	long := "https://cdn.example.net/" + strings.Repeat("a", 40) + "/setup.dmg"
	got := bplistStrings(encodeBplist([]string{long, "https://example.net/download/café"}, false))
	if len(got) != 2 || got[0] != long || got[1] != "https://example.net/download/café" {
		t.Fatalf("array: %q", got)
	}
	if got := bplistStrings(encodeBplist([]string{"https://a.example/x"}, true)); len(got) != 1 || got[0] != "https://a.example/x" {
		t.Fatalf("single: %q", got)
	}
	// Malformed input of every length gives nil, never a panic.
	good := encodeBplist([]string{"https://a.example/x", "https://b.example/y"}, false)
	for i := range good {
		bplistStrings(good[:i])
		bad := append([]byte(nil), good...)
		bad[i] ^= 0xff
		bplistStrings(bad)
	}
	if bplistStrings([]byte("not a plist")) != nil {
		t.Fatal("garbage parsed")
	}
}

func TestClean(t *testing.T) {
	if got := clean(" https://x.example/a\r\nInjected: yes\x00 "); got != "https://x.example/aInjected: yes" {
		t.Fatalf("clean: %q", got)
	}
	if got := clean(strings.Repeat("x", 1000)); len(got) > maxLen+4 {
		t.Fatalf("not bounded: %d", len(got))
	}
}

func TestWhere(t *testing.T) {
	var none *Origin
	for _, c := range []struct {
		o    *Origin
		want string
	}{
		{none, ""},
		{&Origin{URL: "https://u", Referrer: "https://r"}, "https://u"},
		{&Origin{Referrer: `C:\Users\b\Downloads\x.zip`}, `C:\Users\b\Downloads\x.zip`},
		{&Origin{Via: "Safari"}, "the internet, by Safari"},
		{&Origin{}, "the internet"},
	} {
		if got := c.o.Where(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.o, got, c.want)
		}
	}
}
