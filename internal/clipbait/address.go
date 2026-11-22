// Package clipbait catches clippers: malware that watches the clipboard for a
// crypto wallet address and swaps in the attacker's own, so that whatever you
// paste into your wallet sends the money to them.
//
// While nobody is using the PC, a fake wallet address is put on the clipboard
// for a few seconds and watched. Nothing legitimate replaces a wallet address
// with another wallet address, so if that happens, a clipper did it; then
// which program it is gets worked out (see Guard).
//
// This file and wallet.go are the part that doesn't depend on the operating
// system: making bait addresses, and recognising addresses. The clipboard work is Windows
// only, in guard_windows.go.
package clipbait

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"regexp"
	"strings"
)

// Coin is a kind of address a bait can be.
type Coin string

const (
	Bitcoin       Coin = "bitcoin"        // 1...   (pay-to-public-key-hash)
	BitcoinSegwit Coin = "bitcoin-segwit" // bc1q... (pay-to-witness-public-key-hash)
	BitcoinScript Coin = "bitcoin-script" // 3...   (pay-to-script-hash): recognised, not baited
	Ethereum      Coin = "ethereum"       // 0x...  (also BNB Chain, Polygon and the like)
	Tron          Coin = "tron"           // T...   (where most USDT moves)
)

// Coins is the order baits go through: clippers often only look for some.
var Coins = []Coin{Bitcoin, Ethereum, Tron, BitcoinSegwit}

// The patterns clippers use, roughly: they go by shape.
var patterns = map[Coin]*regexp.Regexp{
	Bitcoin:       regexp.MustCompile(`^1[1-9A-HJ-NP-Za-km-z]{25,34}$`),
	BitcoinSegwit: regexp.MustCompile(`^bc1q[02-9ac-hj-np-z]{38}$`),
	BitcoinScript: regexp.MustCompile(`^3[1-9A-HJ-NP-Za-km-z]{25,34}$`),
	Ethereum:      regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`),
	Tron:          regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`),
}

// Other bech32 Bitcoin addresses (taproot, scripts): only recognised.
var bech32 = regexp.MustCompile(`^(bc1|BC1)[02-9ac-hj-np-zAC-HJ-NP-Z]{25,87}$`)

// Looks reports whether s, as a whole, is shaped like a wallet address. A
// clipper swaps an address for one of its own; anything else replacing a bait
// is somebody copying something.
func Looks(s string) bool {
	s = strings.TrimSpace(s)
	if bech32.MatchString(s) {
		return true
	}
	for _, re := range patterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// Lookalike makes an address that has the shape of a real one, so a
// clipper's pattern matches it, but a wrong checksum, so every wallet refuses
// it. Real baits come from Keys (valid, and ABA holds their keys); lookalikes
// are what's used without them, and what the fake clippers in tests swap in.
func Lookalike(c Coin) string {
	for {
		var s string
		switch c {
		case Bitcoin:
			s = base58Bad(0x00)
		case BitcoinScript:
			s = base58Bad(0x05)
		case Tron:
			s = base58Bad(0x41)
		case Ethereum:
			s = ethBad()
		case BitcoinSegwit:
			raw := make([]byte, 20)
			rand.Read(raw)
			good := bech32Segwit("bc", 0, raw)
			last := strings.IndexByte(bech32Charset, good[len(good)-1])
			s = good[:len(good)-1] + string(bech32Charset[(last+1)%32])
		default:
			return ""
		}
		if s != "" && patterns[c].MatchString(s) {
			return s
		}
	}
}

// base58Bad is a Base58Check address with the given version byte and a
// random body, whose checksum is deliberately off by one bit.
func base58Bad(version byte) string {
	payload := make([]byte, 25)
	payload[0] = version
	rand.Read(payload[1:21])
	sum := checksum(payload[:21])
	copy(payload[21:], sum[:])
	payload[24] ^= 0x01
	return base58Encode(payload)
}

func checksum(b []byte) [4]byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	var out [4]byte
	copy(out[:], h2[:4])
	return out
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base, mod := big.NewInt(58), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, bool) {
	n := new(big.Int)
	for _, r := range s {
		i := strings.IndexRune(base58Alphabet, r)
		if i < 0 {
			return nil, false
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	b := n.Bytes()
	for _, r := range s {
		if r != '1' {
			break
		}
		b = append([]byte{0}, b...)
	}
	return b, true
}

// base58Valid reports whether s is a Base58Check string with a correct checksum.
func base58Valid(s string) bool {
	b, ok := base58Decode(s)
	if !ok || len(b) < 5 {
		return false
	}
	sum := checksum(b[:len(b)-4])
	return string(sum[:]) == string(b[len(b)-4:])
}

// ethBad is an Ethereum address in mixed case whose case pattern (the EIP-55
// checksum) is wrong in one letter. Wallets check the case of a mixed-case
// address, so they refuse it. (An all-lowercase address has no checksum at
// all, which is why a bait is never one.)
func ethBad() string {
	raw := make([]byte, 20)
	rand.Read(raw)
	good := eip55(hex.EncodeToString(raw))
	letters := 0
	for _, c := range good {
		if c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			letters++
		}
	}
	if letters < 2 {
		return "" // too few letters to carry a checksum: try another
	}
	k, _ := rand.Int(rand.Reader, big.NewInt(int64(letters)))
	b := []byte(good)
	seen := 0
	for i, c := range b {
		if c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
			if int64(seen) == k.Int64() {
				b[i] = c ^ 0x20 // flip the case of this one letter
				break
			}
			seen++
		}
	}
	upper, lower := false, false
	for _, c := range b {
		upper = upper || c >= 'A' && c <= 'F'
		lower = lower || c >= 'a' && c <= 'f'
	}
	if !upper || !lower {
		return "" // flipping that letter left it all one case, which has no checksum: try another
	}
	return "0x" + string(b)
}

// eip55 puts a lowercase hex address (no 0x) in its checksummed case.
func eip55(lower string) string {
	h := keccak256([]byte(lower))
	b := []byte(lower)
	for i, c := range b {
		nibble := h[i/2] >> 4
		if i%2 == 1 {
			nibble = h[i/2] & 0x0f
		}
		if c >= 'a' && c <= 'f' && nibble >= 8 {
			b[i] = c - 0x20
		}
	}
	return string(b)
}

// ethValid reports whether a mixed-case Ethereum address has a correct checksum.
func ethValid(s string) bool {
	if !patterns[Ethereum].MatchString(s) {
		return false
	}
	return eip55(strings.ToLower(s[2:])) == s[2:]
}
