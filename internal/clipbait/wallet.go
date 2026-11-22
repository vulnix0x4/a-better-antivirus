package clipbait

// Real wallet addresses for baits, whose keys ABA holds.
//
// A bait with a wrong checksum is caught out by a clipper that checks: so
// baits are real addresses, as valid as anyone's. Each comes from its own
// private key, derived from a seed ABA keeps with its other secrets, so that
// if anything were ever sent to one (nobody should: a bait is only on the
// clipboard for seconds, while nobody is at the PC), it isn't lost:
// `aba clipboard key <address>` gives its key.
//
// The cryptography is the standard one (secp256k1 keys, SHA-256 and
// RIPEMD-160 for Bitcoin, Keccak-256 for Ethereum and Tron), written out here
// rather than taken from a library, and checked against published test
// vectors in wallet_test.go. These keys hold no money, so nothing here has to
// be constant-time.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Keys makes bait addresses from a seed.
type Keys struct {
	Seed []byte
	// Record (if set) is told about every address handed out, with the index
	// it was made from: what `aba clipboard key` needs to find its key again.
	Record func(c Coin, index uint64, address string)
}

// NewSeed is a fresh random seed for Keys.
func NewSeed() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

// Bait is a fresh, valid address of coin, recorded.
func (k *Keys) Bait(c Coin) string {
	var b [8]byte
	rand.Read(b[:])
	i := binary.BigEndian.Uint64(b[:]) >> 1
	addr := k.Address(c, i)
	if addr != "" && k.Record != nil {
		k.Record(c, i, addr)
	}
	return addr
}

// Private is the private key behind address index i of coin.
func (k *Keys) Private(c Coin, i uint64) *big.Int {
	for try := uint32(0); ; try++ {
		m := hmac.New(sha256.New, k.Seed)
		fmt.Fprintf(m, "aba clipboard bait|%s|%d|%d", c, i, try)
		d := new(big.Int).SetBytes(m.Sum(nil))
		if d.Sign() > 0 && d.Cmp(curveN) < 0 {
			return d
		}
	}
}

// Address is address index i of coin.
func (k *Keys) Address(c Coin, i uint64) string {
	return addressFor(c, k.Private(c, i))
}

// PrivateText is the private key behind address index i of coin, the way
// wallets import it: WIF for Bitcoin, hex for Ethereum and Tron.
func (k *Keys) PrivateText(c Coin, i uint64) string {
	d := k.Private(c, i)
	switch c {
	case Bitcoin, BitcoinSegwit:
		b := append([]byte{0x80}, pad32(d)...)
		b = append(b, 0x01) // compressed public key
		sum := checksum(b)
		return base58Encode(append(b, sum[:]...))
	}
	return hex.EncodeToString(pad32(d))
}

func addressFor(c Coin, d *big.Int) string {
	x, y := scalarBaseMult(d)
	switch c {
	case Bitcoin:
		return base58Check(0x00, hash160(compressed(x, y)))
	case BitcoinSegwit:
		return bech32Segwit("bc", 0, hash160(compressed(x, y)))
	case Ethereum:
		return "0x" + eip55(hex.EncodeToString(ethHash(x, y)))
	case Tron:
		return base58Check(0x41, ethHash(x, y))
	}
	return ""
}

func compressed(x, y *big.Int) []byte {
	prefix := byte(0x02)
	if y.Bit(0) == 1 {
		prefix = 0x03
	}
	return append([]byte{prefix}, pad32(x)...)
}

// ethHash is the 20 bytes Ethereum and Tron addresses are made of.
func ethHash(x, y *big.Int) []byte {
	h := keccak256(append(pad32(x), pad32(y)...))
	return h[12:]
}

func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	return ripemd160(s[:])
}

func base58Check(version byte, payload []byte) string {
	b := append([]byte{version}, payload...)
	sum := checksum(b)
	return base58Encode(append(b, sum[:]...))
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	return append(make([]byte, 32-len(b)), b...)
}

// ---------- secp256k1 ----------

var (
	curveP  = hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	curveN  = hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	curveGx = hexInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	curveGy = hexInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
)

func hexInt(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 16)
	return n
}

// point is an affine point on the curve; nil x is the point at infinity.
type point struct{ x, y *big.Int }

func (p point) add(q point) point {
	switch {
	case p.x == nil:
		return q
	case q.x == nil:
		return p
	}
	var l *big.Int
	if p.x.Cmp(q.x) == 0 {
		if new(big.Int).Add(p.y, q.y).Mod(new(big.Int).Add(p.y, q.y), curveP).Sign() == 0 {
			return point{}
		}
		// doubling: l = 3x² / 2y
		num := new(big.Int).Mul(p.x, p.x)
		num.Mul(num, big.NewInt(3))
		den := new(big.Int).Lsh(p.y, 1)
		l = num.Mul(num, den.ModInverse(den, curveP))
	} else {
		num := new(big.Int).Sub(q.y, p.y)
		den := new(big.Int).Sub(q.x, p.x)
		den.Mod(den, curveP)
		l = num.Mul(num, den.ModInverse(den, curveP))
	}
	l.Mod(l, curveP)
	x := new(big.Int).Mul(l, l)
	x.Sub(x, p.x).Sub(x, q.x).Mod(x, curveP)
	y := new(big.Int).Sub(p.x, x)
	y.Mul(y, l).Sub(y, p.y).Mod(y, curveP)
	return point{x, y}
}

func scalarBaseMult(d *big.Int) (x, y *big.Int) {
	r, g := point{}, point{curveGx, curveGy}
	for i := d.BitLen() - 1; i >= 0; i-- {
		r = r.add(r)
		if d.Bit(i) == 1 {
			r = r.add(g)
		}
	}
	return r.x, r.y
}

// ---------- bech32 (BIP 173) ----------

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	var out []byte
	for _, c := range hrp {
		out = append(out, byte(c>>5))
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, byte(c&31))
	}
	return out
}

func bech32Segwit(hrp string, version byte, program []byte) string {
	data := []byte{version}
	acc, bits := 0, 0
	for _, b := range program {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data = append(data, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		data = append(data, byte(acc<<(5-bits)&31))
	}
	values := append(bech32HRPExpand(hrp), data...)
	mod := bech32Polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp + "1")
	for _, d := range data {
		b.WriteByte(bech32Charset[d])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(bech32Charset[mod>>(5*(5-i))&31])
	}
	return b.String()
}

// bech32Valid reports whether s is a bech32 string with a correct checksum.
func bech32Valid(s string) bool {
	s = strings.ToLower(s)
	i := strings.LastIndexByte(s, '1')
	if i < 1 || len(s)-i < 7 {
		return false
	}
	var data []byte
	for _, c := range s[i+1:] {
		v := strings.IndexRune(bech32Charset, c)
		if v < 0 {
			return false
		}
		data = append(data, byte(v))
	}
	return bech32Polymod(append(bech32HRPExpand(s[:i]), data...)) == 1
}
