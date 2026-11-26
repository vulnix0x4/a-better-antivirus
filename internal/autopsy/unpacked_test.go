package autopsy

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/alerts"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
)

// A self-unpacking stealer (PyInstaller-like): it unpacks its libraries into
// a folder in Temp and runs code from there, stages what it collects in
// another, and puts a copy of itself in a startup folder. The report counts
// the libraries instead of listing them, lists what it collected, and says
// what it left behind.
func TestRunCountsItsOwnUnpackedCode(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "Temp")
	mei := filepath.Join(tmp, "_MEI1234")
	loot := filepath.Join(tmp, "\u200b \u200c")
	startup := filepath.Join(root, "Startup")
	exe := filepath.Join(root, "Downloads", "cracked.exe")
	write(t, exe, []byte("MZ the stealer itself"))
	for _, n := range []string{"python310.dll", "_ssl.pyd", "select.pyd", "rar.exe"} {
		write(t, filepath.Join(mei, n), []byte("MZ library "+n))
	}
	f, _ := os.Create(filepath.Join(mei, "base_library.zip"))
	zw := zip.NewWriter(f)
	for _, n := range []string{"abc.pyc", "encodings/utf_8.pyc"} {
		e, _ := zw.Create(n)
		e.Write([]byte("code"))
	}
	zw.Close()
	f.Close()
	write(t, filepath.Join(mei, "rarreg.key"), []byte("not code"))
	write(t, filepath.Join(loot, "Wallets", "Exodus", "Location.txt"), []byte("C:\\Users\\x\\AppData\\Roaming\\Exodus"))
	write(t, filepath.Join(startup, "svc.scr"), []byte("MZ the stealer itself"))
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := Case{AlertID: "20261126-102024-4be9", PID: 900, Image: exe, Tree: []uint32{900, 901}, BaitAt: time.Now(), User: config.UserInfo{Profile: root}}
	h := Hooks{
		StartedAt: func(pid uint32) (time.Time, error) { return time.Now().Add(-5 * time.Second), nil },
		CodeFiles: func(pid uint32) ([]string, error) {
			if pid == 901 {
				return []string{exe, filepath.Join(mei, "python310.dll"), filepath.Join(mei, "_ssl.pyd")}, nil
			}
			return []string{exe}, nil
		},
		StagingDirs: func(*Case) []Dir { return []Dir{{Path: tmp, Depth: 3}} },
		StartupDirs: func(*Case) []string { return []string{startup} },
		EvidenceDir: filepath.Join(root, "evidence"),
	}
	a := Run(c, h)

	var listed []string
	for _, s := range a.Staged {
		listed = append(listed, s.Path)
		if strings.HasSuffix(s.Path, ".dll") || strings.HasSuffix(s.Path, ".pyd") || strings.HasSuffix(s.Path, ".zip") || strings.HasSuffix(s.Path, ".exe") {
			t.Errorf("its own code listed as staged: %s (%s)", s.Path, s.What)
		}
	}
	has := func(suffix string) *alerts.Staged {
		for i := range a.Staged {
			if strings.HasSuffix(a.Staged[i].Path, suffix) {
				return &a.Staged[i]
			}
		}
		return nil
	}
	if has("Location.txt") == nil || has("rarreg.key") == nil {
		t.Errorf("what it collected (and a data file beside its code) must stay listed: %v", listed)
	}
	if s := has("svc.scr"); s == nil || s.What != "a copy of the program itself" {
		t.Errorf("startup copy = %+v", s)
	}
	if len(a.Unpacked) != 1 || a.Unpacked[0].Dir != mei || a.Unpacked[0].Files != 5 {
		t.Errorf("unpacked = %+v", a.Unpacked)
	}
	if len(a.Left) != 1 || !strings.Contains(a.Left[0], "a copy of itself") || !strings.Contains(a.Left[0], "svc.scr") {
		t.Errorf("left = %q", a.Left)
	}

	text := PlainText(&alerts.Alert{ID: c.AlertID, Autopsy: a})
	for _, want := range []string{"the program's own code, unpacked there", "What it left behind", "‹U+200B›", "‹U+200C›", "a copy of the program itself"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "python310.dll") || strings.Contains(text, "utf_8.pyc") {
		t.Errorf("report lists its libraries:\n%s", text)
	}
}

func TestVisible(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users\x\AppData\Local\Temp\_MEI1\a.pyd`: `C:\Users\x\AppData\Local\Temp\_MEI1\a.pyd`,
		"C:\\Temp\\   \u200b   \u200c  \\Wallets":   "C:\\Temp\\\"   ‹U+200B›   ‹U+200C›  \"\\Wallets",
		"/tmp/ hidden/x":                                       "/tmp/\" hidden\"/x",
		"/home/me/Documents/budget 2026.txt":                   "/home/me/Documents/budget 2026.txt",
		"C:\\Users\\x\\AppData\\Local\\Temp\\\u200e\\loot.zip": "C:\\Users\\x\\AppData\\Local\\Temp\\\"‹U+200E›\"\\loot.zip",
	} {
		if got := visible(in); got != want {
			t.Errorf("visible(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGluedAddressesAreDropped(t *testing.T) {
	mem := map[string]string{
		"https://discord.com/login":                                   KindURL,
		"https://discord.com/loginemailmorgan@outlook.compasswordv10": KindURL,
		"https://discord.com/login/next":                              KindURL,
		"https://discord.com/login?x=1":                               KindURL,
		"http://191.44.109.252:8000":                                  KindURL,
	}
	got := map[string]bool{}
	for _, a := range Addresses(mem, nil) {
		got[a.Value] = true
	}
	if got["https://discord.com/loginemailmorgan@outlook.compasswordv10"] {
		t.Error("an address with the next field run on is kept")
	}
	for _, v := range []string{"https://discord.com/login", "https://discord.com/login/next", "https://discord.com/login?x=1", "http://191.44.109.252:8000"} {
		if !got[v] {
			t.Errorf("%s dropped", v)
		}
	}
}

func TestReportShowsOnlyAFewMemoryOnlyAddresses(t *testing.T) {
	ap := &alerts.Autopsy{Headline: "x", Evidence: "/e"}
	ap.Addresses = append(ap.Addresses, alerts.Address{Kind: KindDiscord, Value: "https://discord.com/api/webhooks/1/abc", Where: "memory"})
	for i := 0; i < 30; i++ {
		ap.Addresses = append(ap.Addresses, alerts.Address{Kind: KindURL, Value: "https://docs.example.org/page" + strings.Repeat("x", i), Where: "memory"})
	}
	text := PlainText(&alerts.Alert{ID: "a", Autopsy: ap})
	if !strings.Contains(text, "webhooks/1/abc") || !strings.Contains(text, "… and 22 more web addresses found only in its memory") {
		t.Errorf("report:\n%s", text)
	}
	if n := strings.Count(text, "docs.example.org"); n != maxUnsureURLs {
		t.Errorf("%d memory-only addresses shown, want %d", n, maxUnsureURLs)
	}
}

func TestAnEmptyFileIsNoCopyOfAnEmptyBait(t *testing.T) {
	root := t.TempDir()
	bait := filepath.Join(root, "Vivaldi", "LOCK")
	write(t, bait, nil)
	k := newKnown(map[string]string{bait: "MetaMask wallet"}, nil, nil)
	if v, what := k.classify(filepath.Join(root, "Temp", "wct53BD.tmp"), 0, func() (uint32, bool) { return 0, true }); v == isBait {
		t.Errorf("an empty temp file was taken for a bait: %s", what)
	}
}
