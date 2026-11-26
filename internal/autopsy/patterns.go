package autopsy

// Where a stealer sends what it took, from what's in its own memory.
//
// Only generic shapes are looked for, the ones nearly every stealer uses to
// get its haul out: a Telegram bot (its token), a Discord webhook, and plain
// web addresses. No per-family config parsing: that's a signature, one
// family at a time, and stealers change faster than signatures do.
//
// A frozen stealer's memory holds what it collected, too: your cookies, the
// sites in your history. So a plain web address found only in its memory may
// well be yours, not the attacker's. Addresses that are also in its program
// file on disk (which can't hold your data) and addresses of bare IP numbers
// are the attacker's; the rest are listed as found, and kept out of anything
// meant to be shared (see Shareable).

import (
	"bytes"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
)

// Kinds of address.
const (
	KindTelegram = "telegram-bot"
	KindDiscord  = "discord-webhook"
	KindURL      = "url"
	KindConn     = "connection"
)

// maxPerKind caps how many of each kind are kept.
const maxPerKind = 100

// Scanner finds addresses in chunks of memory (or a file), fed in order.
type Scanner struct {
	found map[string]string // value -> kind
	order []string
	count map[string]int
	tail  []byte // the end of the previous chunk, so a match across chunks isn't missed
}

// NewScanner makes an empty scanner.
func NewScanner() *Scanner {
	return &Scanner{found: map[string]string{}, count: map[string]int{}}
}

// overlap is how much of a chunk is carried into the next: longer than any
// address kept.
const overlap = 512

// maxURL is the longest web address kept.
const maxURL = 300

var (
	httpA    = []byte("http")
	tokenA   = []byte(":AA")
	httpA16  = utf16le("http")
	tokenA16 = utf16le(":AA")
)

func utf16le(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		b = append(b, s[i], 0)
	}
	return b
}

// Feed scans one more chunk. The chunks of one region of memory are fed in
// order; between regions, call Break.
func (s *Scanner) Feed(chunk []byte) {
	buf := chunk
	if len(s.tail) > 0 {
		buf = append(append(make([]byte, 0, len(s.tail)+len(chunk)), s.tail...), chunk...)
	}
	start := len(s.tail) // only matches that end in the new part are new
	s.scan(buf, start)
	if len(buf) > overlap {
		s.tail = append(s.tail[:0], buf[len(buf)-overlap:]...)
	} else {
		s.tail = append(s.tail[:0], buf...)
	}
}

// Break says the next chunk doesn't follow on from the last.
func (s *Scanner) Break() { s.tail = s.tail[:0] }

func (s *Scanner) scan(b []byte, newFrom int) {
	for _, a := range []struct {
		anchor []byte
		wide   bool
		fn     func(b []byte, at int, wide bool) (string, string, int)
	}{{httpA, false, urlAt}, {tokenA, false, tokenAt}, {httpA16, true, urlAt}, {tokenA16, true, tokenAt}} {
		for off := 0; ; {
			i := bytes.Index(b[off:], a.anchor)
			if i < 0 {
				break
			}
			at := off + i
			off = at + 1
			kind, v, end := a.fn(b, at, a.wide)
			if v == "" || end <= newFrom {
				continue
			}
			s.add(kind, v)
		}
	}
}

func (s *Scanner) add(kind, v string) {
	if _, ok := s.found[v]; ok {
		return
	}
	if s.count[kind] >= maxPerKind {
		return
	}
	s.count[kind]++
	s.found[v] = kind
	s.order = append(s.order, v)
}

// Found lists what was found, by kind then value.
func (s *Scanner) Found() map[string]string {
	out := make(map[string]string, len(s.found))
	for v, k := range s.found {
		out[v] = k
	}
	return out
}

// narrow reads the text at b[at:], one byte per character (wide: UTF-16LE,
// skipping the zero bytes), while ok says the character belongs, for at most
// max characters. It returns the text and where it ends in b.
func narrow(b []byte, at int, wide bool, max int, ok func(c byte) bool) (string, int) {
	var out []byte
	step := 1
	if wide {
		step = 2
	}
	i := at
	for ; i+step <= len(b) && len(out) < max; i += step {
		c := b[i]
		if wide && b[i+1] != 0 {
			break
		}
		if !ok(c) {
			break
		}
		out = append(out, c)
	}
	return string(out), i
}

func urlChar(c byte) bool {
	return c > 0x20 && c < 0x7f && c != '"' && c != '\'' && c != '<' && c != '>' && c != '\\' && c != '`' && c != '{' && c != '}' && c != '|' && c != '^'
}

// urlAt reads a web address starting at b[at:] ("http…").
func urlAt(b []byte, at int, wide bool) (kind, v string, end int) {
	raw, end := narrow(b, at, wide, maxURL+1, urlChar)
	if len(raw) > maxURL {
		return "", "", end
	}
	raw = strings.TrimRight(raw, ".,;:)]")
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", "", end
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !plausibleHost(u.Hostname()) {
		return "", "", end
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case (host == "discord.com" || host == "discordapp.com" || host == "canary.discord.com" || host == "ptb.discord.com") && strings.HasPrefix(u.Path, "/api/webhooks/"):
		parts := strings.Split(strings.TrimPrefix(u.Path, "/api/webhooks/"), "/")
		if len(parts) >= 2 && allDigits(parts[0]) && len(parts[1]) >= 20 {
			return KindDiscord, "https://" + host + "/api/webhooks/" + parts[0] + "/" + parts[1], end
		}
		return "", "", end
	case host == "api.telegram.org" && strings.HasPrefix(u.Path, "/bot"):
		tok := strings.SplitN(strings.TrimPrefix(u.Path, "/bot"), "/", 2)[0]
		if botToken(tok) {
			return KindTelegram, tok, end
		}
		return "", "", end
	}
	if boilerplate(host) {
		return "", "", end
	}
	return KindURL, raw, end
}

// tokenAt reads a Telegram bot token around b[at:] (":AA…"): the bot's number
// before it, its secret after.
func tokenAt(b []byte, at int, wide bool) (kind, v string, end int) {
	step := 1
	if wide {
		step = 2
	}
	i := at
	for n := 0; i-step >= 0 && n < 11; n++ {
		c := b[i-step]
		if wide && b[i-step+1] != 0 {
			break
		}
		if c < '0' || c > '9' {
			break
		}
		i -= step
	}
	digits, _ := narrow(b, i, wide, 11, func(c byte) bool { return c >= '0' && c <= '9' })
	secret, end := narrow(b, at+step, wide, 40, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
	})
	tok := digits + ":" + secret
	if !botToken(tok) {
		return "", "", end
	}
	return KindTelegram, tok, end
}

// botToken: a Telegram bot token is the bot's number (8 to 10 digits), a
// colon and 35 characters starting with "AA".
func botToken(t string) bool {
	id, secret, ok := strings.Cut(t, ":")
	if !ok || len(id) < 8 || len(id) > 10 || !allDigits(id) || len(secret) != 35 || !strings.HasPrefix(secret, "AA") {
		return false
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// plausibleHost: a real host name or IP address, not a fragment of text.
func plausibleHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if !strings.Contains(h, ".") || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	tld := labels[len(labels)-1]
	if len(tld) < 2 || allDigits(tld) {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// boilerplate hosts appear in nearly every program (XML namespaces,
// certificate checks, standards bodies): never where a stealer sends.
func boilerplate(host string) bool {
	for _, b := range []string{"www.w3.org", "w3.org", "schemas.microsoft.com", "schemas.xmlsoap.org", "schemas.openxmlformats.org",
		"www.apple.com", "ns.adobe.com", "purl.org", "xml.org", "www.xml.org", "ocsp.digicert.com", "crl3.digicert.com", "crl4.digicert.com",
		"www.digicert.com", "cacerts.digicert.com", "ocsp.apple.com", "crl.apple.com", "www.microsoft.com", "go.microsoft.com",
		"crl.microsoft.com", "ocsp.sectigo.com", "crl.sectigo.com", "ocsp.comodoca.com", "crl.comodoca.com", "ocsp.globalsign.com",
		"crl.globalsign.com", "secure.globalsign.com", "ocsp.usertrust.com", "crl.usertrust.com", "json-schema.org", "golang.org", "go.dev",
		// the names of picture metadata (a screenshot it took carries them)
		"ns.microsoft.com", "cipa.jp", "iptc.org", "www.iptc.org", "ns.useplus.org", "www.npes.org"} {
		if host == b {
			return true
		}
	}
	return false
}

// Addresses turns what was found in memory and in the program file into the
// list the alert keeps.
func Addresses(inMemory, inFile map[string]string) []alerts.Address {
	where := map[string]string{}
	kinds := map[string]string{}
	for v, k := range inMemory {
		where[v], kinds[v] = "memory", k
	}
	for v, k := range inFile {
		if where[v] == "memory" {
			where[v] = "memory+file"
		} else {
			where[v] = "file"
		}
		kinds[v] = k
	}
	var out []alerts.Address
	for v, w := range where {
		if w == "memory" && kinds[v] == KindURL && glued(v, kinds) {
			continue
		}
		out = append(out, alerts.Address{Kind: kinds[v], Value: v, Where: w})
	}
	rank := map[string]int{KindTelegram: 0, KindDiscord: 1, KindURL: 2, KindConn: 3}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		if (out[i].Where == "memory") != (out[j].Where == "memory") {
			return out[j].Where == "memory" // the attacker's for certain first
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// glued: v is another address found with more text run on after it, not an
// address of its own. In memory, the fields of a record lie end to end (a
// saved login's site, then its user name, with nothing between), and the
// scan reads on into the next field: "https://site/login" then
// "https://site/loginemailname@mail.compassword…". Only a continuation that
// a web address can't have after that point counts as glued: a path, query
// or fragment going on ("/", "?", "#", "&", "=") doesn't.
func glued(v string, kinds map[string]string) bool {
	for u, k := range kinds {
		if k != KindURL || len(u) >= len(v) || !strings.HasPrefix(v, u) {
			continue
		}
		if !strings.ContainsRune("/?#&=;%", rune(v[len(u)])) && !strings.HasSuffix(u, "/") {
			return true
		}
	}
	return false
}

// Shareable says whether an address is certainly the attacker's, not
// something of yours the stealer was holding: a bot token or webhook, an
// address that's in its program file, a bare IP address, or a connection it
// had open.
func Shareable(kind, value, where string) bool {
	switch kind {
	case KindTelegram, KindDiscord, KindConn:
		return true
	case KindURL:
		if where == "file" || where == "memory+file" {
			return true
		}
		if u, err := url.Parse(value); err == nil && net.ParseIP(u.Hostname()) != nil {
			return true
		}
	}
	return false
}
