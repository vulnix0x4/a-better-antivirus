package clipbait

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestRIPEMD160(t *testing.T) {
	// The test vectors from the RIPEMD-160 paper.
	for in, want := range map[string]string{
		"":                           "9c1185a5c5e9fc54612808977ee8f548b2258d31",
		"a":                          "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
		"abc":                        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
		"message digest":             "5d0689ef49d2fae572b881b123a85ffa21595f36",
		"abcdefghijklmnopqrstuvwxyz": "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
	} {
		if got := hex.EncodeToString(ripemd160([]byte(in))); got != want {
			t.Errorf("ripemd160(%q) = %s, want %s", in, got, want)
		}
	}
}

// The key 1, whose public key is the curve's generator: its addresses are
// published everywhere (BIP 173 has the segwit one).
func TestAddressesOfKeyOne(t *testing.T) {
	one := big.NewInt(1)
	for c, want := range map[Coin]string{
		Bitcoin:       "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
		BitcoinSegwit: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		Ethereum:      "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
	} {
		if got := addressFor(c, one); got != want {
			t.Errorf("%s address of key 1 = %s, want %s", c, got, want)
		}
	}
	x, y := scalarBaseMult(one)
	if hex.EncodeToString(hash160(compressed(x, y))) != "751e76e8199196d454941c45d1b3a323f1433bd6" {
		t.Error("hash160 of the generator")
	}
	// Tron is the Ethereum address's 20 bytes, version 0x41, Base58Check.
	if tr := addressFor(Tron, one); !base58Valid(tr) || !strings.HasPrefix(tr, "T") {
		t.Errorf("tron address of key 1: %s", tr)
	}
}

// Bigger keys exercise the curve arithmetic properly.
func TestCurveMath(t *testing.T) {
	// 2G and 3G (from the SEC 2 / well-known secp256k1 tables).
	for k, wantX := range map[int64]string{
		2: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
		3: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	} {
		x, _ := scalarBaseMult(big.NewInt(k))
		if hex.EncodeToString(pad32(x)) != wantX {
			t.Errorf("%dG: x = %x, want %s", k, x, wantX)
		}
	}
	// n-1 times G is -G: same x as G.
	nm1 := new(big.Int).Sub(curveN, big.NewInt(1))
	x, y := scalarBaseMult(nm1)
	if x.Cmp(curveGx) != 0 || new(big.Int).Add(y, curveGy).Cmp(curveP) != 0 {
		t.Error("(n-1)G should be -G")
	}
	// A point found by adding must be on the curve: y² = x³ + 7.
	x, y = scalarBaseMult(hexInt("2f5e8a3b9c0d1e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f"))
	lhs := new(big.Int).Mul(y, y)
	rhs := new(big.Int).Exp(x, big.NewInt(3), nil)
	rhs.Add(rhs, big.NewInt(7))
	if lhs.Mod(lhs, curveP).Cmp(rhs.Mod(rhs, curveP)) != 0 {
		t.Error("a multiple of G isn't on the curve")
	}
}

func TestWIF(t *testing.T) {
	// The compressed-key WIF of private key 1.
	b := append([]byte{0x80}, pad32(big.NewInt(1))...)
	b = append(b, 0x01)
	sum := checksum(b)
	if got := base58Encode(append(b, sum[:]...)); got != "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn" {
		t.Errorf("WIF of key 1 = %s", got)
	}
}

// Real baits: valid addresses, the shape clippers look for, each different,
// and the same key again from the same seed and index.
func TestKeyedBaits(t *testing.T) {
	var recorded []string
	k := &Keys{Seed: NewSeed(), Record: func(c Coin, i uint64, a string) { recorded = append(recorded, a) }}
	seen := map[string]bool{}
	for _, c := range Coins {
		for i := 0; i < 20; i++ {
			b := k.Bait(c)
			if !patterns[c].MatchString(b) || !Looks(b) {
				t.Fatalf("%s bait %q doesn't have the shape clippers look for", c, b)
			}
			if seen[b] {
				t.Fatalf("%s bait %q came up twice", c, b)
			}
			seen[b] = true
			valid := false
			switch c {
			case Ethereum:
				valid = ethValid(b) || strings.ToLower(b) == b
			case BitcoinSegwit:
				valid = bech32Valid(b)
			default:
				valid = base58Valid(b)
			}
			if !valid {
				t.Fatalf("%s bait %q isn't a valid address", c, b)
			}
		}
	}
	if len(recorded) != 20*len(Coins) {
		t.Fatalf("recorded %d baits, want %d", len(recorded), 20*len(Coins))
	}
	again := &Keys{Seed: k.Seed}
	if k.Address(Ethereum, 42) != again.Address(Ethereum, 42) || k.Address(Ethereum, 42) == k.Address(Ethereum, 43) {
		t.Fatal("addresses must follow from seed and index")
	}
	if k.Address(Bitcoin, 7) == (&Keys{Seed: NewSeed()}).Address(Bitcoin, 7) {
		t.Fatal("different seeds, same address")
	}
	// The key printed for an address is the one it's made from.
	d := k.Private(Bitcoin, 7)
	if addressFor(Bitcoin, d) != k.Address(Bitcoin, 7) || !strings.HasPrefix(k.PrivateText(Bitcoin, 7), "K") && !strings.HasPrefix(k.PrivateText(Bitcoin, 7), "L") {
		t.Fatalf("bitcoin key: %s", k.PrivateText(Bitcoin, 7))
	}
	if len(k.PrivateText(Ethereum, 7)) != 64 {
		t.Fatalf("ethereum key: %s", k.PrivateText(Ethereum, 7))
	}
}

func TestRecordAndLookup(t *testing.T) {
	dir := t.TempDir()
	k := KeysFromSeed(hex.EncodeToString(NewSeed()), dir, t.Logf)
	a := k.Bait(Tron)
	b := k.Bait(BitcoinSegwit)
	for _, addr := range []string{a, b} {
		c, i, _, ok := Lookup(dir, addr)
		if !ok || k.Address(c, i) != addr {
			t.Fatalf("%s: lookup gave %s/%d (found %v)", addr, c, i, ok)
		}
	}
	if _, _, _, ok := Lookup(dir, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); ok {
		t.Fatal("found an address that was never handed out")
	}
	if KeysFromSeed("nonsense", dir, t.Logf) != nil {
		t.Fatal("a bad seed should give no keys")
	}
}
