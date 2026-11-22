package origin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseZone(t *testing.T) {
	for _, c := range []struct {
		in, url, ref string
		marked       bool
	}{
		{"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://free-tools.example/get\r\nHostUrl=https://cdn.example/setup.exe\r\n",
			"https://cdn.example/setup.exe", "https://free-tools.example/get", true},
		// Unpacked from a downloaded zip by Explorer: the archive is the referrer.
		{"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\b\\Downloads\\crack.zip\r\n", "", `C:\Users\b\Downloads\crack.zip`, true},
		{"\ufeff[ZoneTransfer]\nZoneId=3\nHostUrl=about:internet\n", "", "", true},
		{"[ZoneTransfer]\r\nZoneId=4\r\n", "", "", true},
		{"[ZoneTransfer]\r\nZoneId=2\r\nHostUrl=https://intranet/x.exe\r\n", "", "", false},
		{"[ZoneTransfer]\r\nZoneId=0\r\n", "", "", false},
		{"garbage", "", "", false},
	} {
		o := parseZone(`C:\x.exe`, c.in)
		if (o != nil) != c.marked {
			t.Errorf("%q: marked=%v", c.in, o != nil)
			continue
		}
		if o != nil && (o.URL != c.url || o.Referrer != c.ref || o.File != `C:\x.exe`) {
			t.Errorf("%q: got %+v", c.in, o)
		}
	}
}

func TestOfReadsTheStream(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "setup.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if Of(exe) != nil {
		t.Fatal("unmarked file has an origin")
	}
	if err := os.WriteFile(exe+":Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://cdn.example/setup.exe\r\n"), 0o644); err != nil {
		t.Skipf("no alternate data streams here: %v", err)
	}
	o := Find("", filepath.Join(dir, "missing.exe"), exe)
	if o == nil || o.URL != "https://cdn.example/setup.exe" || o.File != exe {
		t.Fatalf("got %+v", o)
	}
}
