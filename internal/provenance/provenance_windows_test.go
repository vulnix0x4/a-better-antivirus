package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogSignedSystemBinary(t *testing.T) {
	r := Verify(filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`))
	if !r.Valid || !strings.Contains(r.Signer, "Microsoft") {
		t.Fatalf("cmd.exe: got %+v, want valid Microsoft signature", r)
	}
}

func TestUnsignedTestBinary(t *testing.T) {
	exe, _ := os.Executable() // go test binaries are unsigned
	r := Verify(exe)
	if r.Signed || r.Valid {
		t.Fatalf("test binary: got %+v, want unsigned", r)
	}
}

func TestTamperedCopyIsNotValid(t *testing.T) {
	src := filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip(err)
	}
	// A renamed copy outside System32 is still catalog-valid (same hash)…
	dir := t.TempDir()
	cp := filepath.Join(dir, "MsMpEng.exe")
	os.WriteFile(cp, b, 0o644)
	if r := Verify(cp); !r.Valid {
		t.Fatalf("identical copy should still verify: %+v", r)
	}
	// …but one flipped byte must not be.
	b[len(b)/2] ^= 0xff
	bad := filepath.Join(dir, "evil.exe")
	os.WriteFile(bad, b, 0o644)
	if r := Verify(bad); r.Valid {
		t.Fatalf("tampered copy verified: %+v", r)
	}
}

// A signed file is verified, then swapped for something else at the same
// path. The earlier "signed" result must not carry over to the new file.
func TestResultIsNotReusedForADifferentFileAtTheSamePath(t *testing.T) {
	signed, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), `System32\cmd.exe`))
	if err != nil {
		t.Skip(err)
	}
	self, _ := os.Executable()
	unsigned, err := os.ReadFile(self)
	if err != nil {
		t.Skip(err)
	}
	p := filepath.Join(t.TempDir(), "tool.exe")
	os.WriteFile(p, signed, 0o644)
	if r := Verify(p); !r.Valid {
		t.Fatalf("signed copy: %+v", r)
	}
	// Replaced by a different file (a new file under the old name)...
	os.Remove(p)
	os.WriteFile(p, unsigned, 0o644)
	if r := Verify(p); r.Valid {
		t.Fatalf("an unsigned file inherited the signature of the file it replaced: %+v", r)
	}
	// ...and overwritten in place.
	os.WriteFile(p, signed, 0o644)
	if r := Verify(p); !r.Valid {
		t.Fatalf("signed again: %+v", r)
	}
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0o644)
	f.Write(unsigned)
	f.Close()
	if r := Verify(p); r.Valid {
		t.Fatalf("a file overwritten in place kept its old signature result: %+v", r)
	}
}
