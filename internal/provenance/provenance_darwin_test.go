package provenance

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinApple(t *testing.T) {
	for _, p := range []string{"/bin/ls", "/usr/bin/osascript", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"} {
		r := Verify(p)
		if !r.Valid || r.Signer != AppleSigner {
			t.Errorf("%s: %+v", p, r)
		}
	}
}

func TestDarwinUnsigned(t *testing.T) {
	dir := t.TempDir()
	// A copy of an Apple program, changed throughout: its signature no
	// longer matches.
	b, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	for i := 4096; i < len(b)-4096; i += 4096 {
		b[i] ^= 0xff
	}
	tampered := filepath.Join(dir, "echo")
	os.WriteFile(tampered, b, 0o755)
	if r := Verify(tampered); r.Valid {
		t.Errorf("tampered copy: %+v", r)
	}
	// What a program built on a Mac gets: an ad-hoc signature.
	adhoc := filepath.Join(dir, "adhoc")
	os.WriteFile(adhoc, mustRead(t, "/bin/echo"), 0o755)
	if out, err := exec.Command("/usr/bin/codesign", "--force", "-s", "-", adhoc).CombinedOutput(); err != nil {
		t.Skipf("codesign: %v %s", err, out)
	}
	if r := Verify(adhoc); r.Valid || r.Signed {
		t.Errorf("ad-hoc: %+v", r)
	}
	// Plain data isn't code at all.
	txt := filepath.Join(dir, "notes.txt")
	os.WriteFile(txt, []byte("hello"), 0o644)
	if r := Verify(txt); r.Valid || r.Signed {
		t.Errorf("text file: %+v", r)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDarwinJudgeSignature(t *testing.T) {
	devID := codesignInfo{authority: []string{"Developer ID Application: Google LLC (EQHXZ8M8AV)", "Developer ID Certification Authority", "Apple Root CA"}, teamID: "EQHXZ8M8AV"}
	if r := judgeSignature(devID, true, ""); !r.Valid || r.Signer != "Google LLC (EQHXZ8M8AV)" {
		t.Errorf("Developer ID: %+v", r)
	}
	if r := judgeSignature(devID, false, "a sealed resource is missing or invalid"); r.Valid || !r.Signed {
		t.Errorf("Developer ID that doesn't verify: %+v", r)
	}
	dev := codesignInfo{authority: []string{"Apple Development: someone (ABCDE12345)", "Apple Worldwide Developer Relations Certification Authority", "Apple Root CA"}}
	if r := judgeSignature(dev, true, ""); r.Valid {
		t.Errorf("development signature: %+v", r)
	}
	// Someone's own certificate authority calling itself Apple's.
	fake := codesignInfo{authority: []string{"Software Signing", "My CA"}}
	if r := judgeSignature(fake, true, ""); r.Valid {
		t.Errorf("fake chain: %+v", r)
	}
	out := "Executable=/tmp/x\nIdentifier=x-55554944\nFormat=Mach-O thin (arm64)\nSignature=adhoc\nTeamIdentifier=not set\n"
	if ci := parseCodesign(out); !ci.adhoc || ci.teamID != "" {
		t.Errorf("parse: %+v", ci)
	}
}
