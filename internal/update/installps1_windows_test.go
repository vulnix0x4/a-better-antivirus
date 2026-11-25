package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// install.ps1 checks the release's signature with its own ed25519 (Windows
// PowerShell has none). This runs that code, taken out of the script, on
// signatures made here, and expects the answer Go's crypto/ed25519 gives for
// every one of them: good ones, and ones that must be refused.
func TestInstallScriptChecksSignaturesLikeGo(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(string(src), "\r\n", "\n")

	// The script carries the same release key as the updater.
	if !strings.Contains(script, "$releaseKey = '"+PublicKey+"'") {
		t.Fatal("install.ps1 doesn't carry the release key of internal/update")
	}
	_, after, ok := strings.Cut(script, "# >>> ed25519\n")
	fn, _, ok2 := strings.Cut(after, "# <<< ed25519")
	if !ok || !ok2 || !strings.Contains(fn, "function Test-Ed25519") {
		t.Fatal("install.ps1: no Test-Ed25519 between the ed25519 markers")
	}

	type tc struct {
		Name, Key, Msg, Sig string
		want                bool
	}
	b64 := base64.StdEncoding.EncodeToString
	var cases []tc
	add := func(name string, key, msg, sig []byte) {
		want := len(key) == ed25519.PublicKeySize && ed25519.Verify(key, msg, sig)
		cases = append(cases, tc{name, b64(key), b64(msg), b64(sig), want})
	}
	flip := func(b []byte, i int, bit byte) []byte {
		c := bytes.Clone(b)
		c[i] ^= bit
		return c
	}

	// RFC 8032, section 7.1: tests 1 to 3.
	for i, v := range [][3]string{
		{"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
			"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
		{"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
			"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
		{"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
			"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	} {
		key, _ := hex.DecodeString(v[0])
		msg, _ := hex.DecodeString(v[1])
		sig, _ := hex.DecodeString(v[2])
		add("RFC 8032 test "+string(rune('1'+i)), key, msg, sig)
		if !cases[len(cases)-1].want {
			t.Fatalf("RFC 8032 test %d doesn't verify in Go", i+1)
		}
	}

	order, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	for i, n := range []int{0, 1, 64, 380, 5000} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		msg := make([]byte, n)
		rand.Read(msg)
		sig := ed25519.Sign(priv, msg)
		name := "key " + string(rune('a'+i)) + ": "
		add(name+"a good signature", pub, msg, sig)
		add(name+"another key", other, msg, sig)
		add(name+"a bit of R flipped", pub, msg, flip(sig, i*5, 1<<uint(i)))
		add(name+"a bit of s flipped", pub, msg, flip(sig, 32+i*6, 0x10))
		add(name+"the key's sign bit flipped", flip(pub, 31, 0x80), msg, sig)
		if n > 0 {
			add(name+"a bit of the message flipped", pub, flip(msg, n/2, 2), sig)
			add(name+"the message cut short", pub, msg[:n-1], sig)
		}
		add(name+"one byte added to the message", pub, append(bytes.Clone(msg), 0), sig)
		// s + L signs the same thing in a sloppy verifier; it must be refused.
		s := new(big.Int).SetBytes(reverse(sig[32:]))
		if s.Add(s, order); s.BitLen() <= 256 {
			add(name+"s plus the group order", pub, msg, append(bytes.Clone(sig[:32]), reverse(s.FillBytes(make([]byte, 32)))...))
		}
		add(name+"a signature one byte short", pub, msg, sig[:63])
		add(name+"an all-zero signature", pub, msg, make([]byte, 64))
	}
	// Keys that aren't points, or aren't written the one right way.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("SHA256SUMS")
	sig := ed25519.Sign(priv, msg)
	ff := bytes.Repeat([]byte{0xff}, 32)
	add("a key of all ones", ff, msg, sig)
	add("a key that is y = p", append([]byte{0xed}, append(bytes.Repeat([]byte{0xff}, 30), 0x7f)...), msg, sig)
	add("an all-zero key", make([]byte, 32), msg, sig)
	add("a key one byte short", pub[:31], msg, sig)
	two := make([]byte, 32)
	two[0] = 2 // y = 2 is on no point of the curve
	add("a key that is no point", two, msg, sig)

	dir := t.TempDir()
	js, _ := json.Marshal(cases)
	if err := os.WriteFile(filepath.Join(dir, "cases.json"), js, 0o644); err != nil {
		t.Fatal(err)
	}
	harness := "$ErrorActionPreference = 'Stop'\n" + fn + `
foreach ($c in (Get-Content -Raw (Join-Path $PSScriptRoot 'cases.json') | ConvertFrom-Json)) {
    $r = Test-Ed25519 ([Convert]::FromBase64String($c.Key)) ([Convert]::FromBase64String($c.Msg)) ([Convert]::FromBase64String($c.Sig))
    if ($r -isnot [bool]) { $r = "not a bool: $r" }
    Write-Output ("{0}|{1}" -f $r, $c.Name)
}
`
	ps1 := filepath.Join(dir, "check.ps1")
	if err := os.WriteFile(ps1, []byte(harness), 0o644); err != nil {
		t.Fatal(err)
	}

	// Windows PowerShell 5.1 is what `irm | iex` runs in for most people;
	// PowerShell 7 where it's installed.
	ran := 0
	for _, shell := range []string{"powershell.exe", "pwsh.exe"} {
		exe, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		ran++
		out, err := exec.Command(exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", ps1).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", shell, err, out)
		}
		lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(out), "\r\n", "\n")), "\n")
		if len(lines) != len(cases) {
			t.Fatalf("%s: %d answers for %d cases:\n%s", shell, len(lines), len(cases), out)
		}
		good := 0
		for i, c := range cases {
			want := "False|" + c.Name
			if c.want {
				want = "True|" + c.Name
				good++
			}
			if lines[i] != want {
				t.Errorf("%s: got %q, want %q", shell, lines[i], want)
			}
		}
		t.Logf("%s: %d signatures, %d of them good, all answered like Go", shell, len(cases), good)
	}
	if ran == 0 {
		t.Skip("no PowerShell here")
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
