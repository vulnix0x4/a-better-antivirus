package clipbait

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestKeccak256(t *testing.T) {
	for in, want := range map[string]string{
		"":    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		// longer than one block (136 bytes)
		strings.Repeat("a", 200): "",
	} {
		got := keccak256([]byte(in))
		if want != "" && hex.EncodeToString(got[:]) != want {
			t.Errorf("keccak256(%q) = %x, want %s", in, got, want)
		}
	}
}

func TestEIP55(t *testing.T) {
	// The examples from EIP-55 itself.
	for _, addr := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	} {
		if !ethValid(addr) {
			t.Errorf("%s: a correct checksum was refused", addr)
		}
	}
}

func TestBase58Check(t *testing.T) {
	// The very first Bitcoin address, and a well-known script address.
	for _, addr := range []string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"} {
		if !base58Valid(addr) {
			t.Errorf("%s: a correct checksum was refused", addr)
		}
		if b, _ := base58Decode(addr); base58Encode(b) != addr {
			t.Errorf("%s: decode/encode doesn't round-trip", addr)
		}
	}
}

// Every bait must look real to a clipper and be refused by any wallet.
func TestBaitsLookRealButAreInvalid(t *testing.T) {
	for _, c := range Coins {
		seen := map[string]bool{}
		for i := 0; i < 3000; i++ {
			b := Bait(c)
			if !patterns[c].MatchString(b) || !Looks(b) {
				t.Fatalf("%s bait %q doesn't have the shape clippers look for", c, b)
			}
			if seen[b] {
				t.Fatalf("%s bait %q came up twice", c, b)
			}
			seen[b] = true
			switch c {
			case Ethereum:
				if ethValid(b) {
					t.Fatalf("ethereum bait %q has a valid checksum", b)
				}
				if strings.ToLower(b) == b || strings.ToUpper(b[2:]) == b[2:] {
					t.Fatalf("ethereum bait %q isn't mixed case, so wallets wouldn't check it", b)
				}
			default:
				if base58Valid(b) {
					t.Fatalf("%s bait %q has a valid checksum", c, b)
				}
			}
		}
	}
	if !strings.HasPrefix(Bait(Tron), "T") || !strings.HasPrefix(Bait(BitcoinScript), "3") || !strings.HasPrefix(Bait(Bitcoin), "1") {
		t.Fatal("wrong leading character")
	}
}

func TestLooks(t *testing.T) {
	for _, s := range []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", " 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy\n",
		"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE",
	} {
		if !Looks(s) {
			t.Errorf("%q should look like an address", s)
		}
	}
	for _, s := range []string{"", "hello", "https://example.com", "0x123", "pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now"} {
		if Looks(s) {
			t.Errorf("%q shouldn't look like an address", s)
		}
	}
}
