package autopsy

import (
	"strings"
	"testing"
)

const tok = "7134567890:AAHk3n2Lq9xZr8Yv6Tt5Ww4Uu3Ss2Rr1Qq0"

func scanAll(chunks ...[]byte) map[string]string {
	s := NewScanner()
	for _, c := range chunks {
		s.Feed(c)
	}
	return s.Found()
}

func TestFindsBotTokensWebhooksAndURLs(t *testing.T) {
	mem := []byte("\x00\x01junk https://api.telegram.org/bot" + tok + "/sendDocument?chat_id=1 more " +
		"POST https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEF0123456789_- tail " +
		"gate=http://185.199.1.7:8080/upload.php\x00 and http://www.w3.org/2001/XMLSchema and http://notahost/x")
	got := scanAll(mem)
	want := map[string]string{
		tok: KindTelegram,
		"https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEF0123456789_-": KindDiscord,
		"http://185.199.1.7:8080/upload.php": KindURL,
	}
	for v, k := range want {
		if got[v] != k {
			t.Errorf("missing %s %s; got %v", k, v, got)
		}
	}
	for v := range got {
		if strings.Contains(v, "w3.org") || strings.Contains(v, "notahost") {
			t.Errorf("kept %s", v)
		}
	}
}

func TestBareTokenAndUTF16(t *testing.T) {
	wide := utf16le("token=" + tok + ";url=https://evil.example.net/p")
	got := scanAll(wide)
	if got[tok] != KindTelegram {
		t.Errorf("UTF-16 token not found: %v", got)
	}
	if got["https://evil.example.net/p"] != KindURL {
		t.Errorf("UTF-16 URL not found: %v", got)
	}
	if got := scanAll([]byte("x" + tok + "x")); got[tok] != "" {
		t.Errorf("a token run into other text was kept: %v", got)
	}
	if got := scanAll([]byte(" 12:AAxyz ")); len(got) != 0 {
		t.Errorf("not a token: %v", got)
	}
}

func TestMatchAcrossChunks(t *testing.T) {
	s := "....https://exfil.example.org/collect?id=42 ...."
	mid := strings.Index(s, "exfil")
	got := scanAll([]byte(s[:mid]), []byte(s[mid:]))
	if got["https://exfil.example.org/collect?id=42"] != KindURL {
		t.Errorf("split URL not found: %v", got)
	}
}

func TestShareable(t *testing.T) {
	cases := []struct {
		kind, v, where string
		want           bool
	}{
		{KindTelegram, tok, "memory", true},
		{KindURL, "https://mail.example.com/inbox", "memory", false}, // could be the person's own
		{KindURL, "https://panel.example.com/gate", "file", true},
		{KindURL, "http://185.199.1.7/upload", "memory", true},
		{KindConn, "185.199.1.7:443", "connection", true},
	}
	for _, c := range cases {
		if got := Shareable(c.kind, c.v, c.where); got != c.want {
			t.Errorf("Shareable(%s, %s, %s) = %v", c.kind, c.v, c.where, got)
		}
	}
}

func TestAddressesOrder(t *testing.T) {
	out := Addresses(map[string]string{"https://a.example.com/": KindURL, tok: KindTelegram}, map[string]string{"https://b.example.com/": KindURL, "https://a.example.com/": KindURL})
	if len(out) != 3 || out[0].Kind != KindTelegram || out[1].Where != "memory+file" || out[2].Where != "file" {
		t.Errorf("addresses = %+v", out)
	}
}

func BenchmarkScan(b *testing.B) {
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i*7 + i/3)
	}
	b.SetBytes(int64(len(chunk)))
	for i := 0; i < b.N; i++ {
		s := NewScanner()
		s.Feed(chunk)
	}
}
