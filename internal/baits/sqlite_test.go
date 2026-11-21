package baits

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var fakeDBs = map[string]func(*Gen) []byte{
	"Login Data": genLoginData, "Cookies": genCookies, "Web Data": genWebData, "key4.db": genKey4, "cookies.sqlite": genMozCookies,
}

// The fake databases must hold up to a look at the folder listing: never the
// one-page size of an empty database, and not the same size on every install.
func TestFakeDatabasesLookUsed(t *testing.T) {
	for name, gen := range fakeDBs {
		sizes := map[int]bool{}
		for i := 0; i < 30; i++ {
			db := gen(NewGen())
			be := binary.BigEndian
			if !bytes.HasPrefix(db, []byte("SQLite format 3\x00")) || len(db)%sqlitePage != 0 || int(be.Uint32(db[28:]))*sqlitePage != len(db) {
				t.Fatalf("%s: not a well-formed database file (%d bytes)", name, len(db))
			}
			if len(db) < 5*sqlitePage {
				t.Fatalf("%s: %d bytes: an empty-looking database gives a decoy away", name, len(db))
			}
			if be.Uint32(db[92:]) != be.Uint32(db[24:]) {
				t.Fatalf("%s: header says its size can't be trusted", name)
			}
			sizes[len(db)] = true
		}
		if len(sizes) < 4 {
			t.Errorf("%s: only %d different sizes over 30 installs", name, len(sizes))
		}
	}
}

// Row encoding, against values worked out by hand from the file format.
func TestSQLiteRecordEncoding(t *testing.T) {
	got := sqlRecord([]any{nil, 0, 1, 5, 300, "ab", []byte{9}})
	want := []byte{8, 0, 8, 9, 1, 2, 17, 14, 5, 0x01, 0x2c, 'a', 'b', 9}
	if !bytes.Equal(got, want) {
		t.Fatalf("record = % x, want % x", got, want)
	}
	for v, want := range map[uint64][]byte{0: {0}, 127: {0x7f}, 128: {0x81, 0x00}, 16383: {0xff, 0x7f}, 16384: {0x81, 0x80, 0x00}} {
		if got := sqlVarint(v); !bytes.Equal(got, want) {
			t.Errorf("varint(%d) = % x, want % x", v, got, want)
		}
	}
}

// The real test: SQLite itself opens them, finds nothing wrong, and a
// stealer's query returns rows. (Uses Python's sqlite3 where there is one.)
func TestFakeDatabasesOpenInSQLite(t *testing.T) {
	py, err := exec.LookPath("python")
	if err != nil {
		t.Skip("no python to check the databases with")
	}
	dir := t.TempDir()
	for name, gen := range fakeDBs {
		for i := 0; i < 5; i++ {
			os.WriteFile(filepath.Join(dir, name+"-"+string(rune('0'+i))), gen(NewGen()), 0o644)
		}
	}
	script := `
import sqlite3, sys, os, glob
queries = {
 "Login Data": "SELECT origin_url, username_value, password_value FROM logins",
 "Cookies": "SELECT host_key, name, encrypted_value FROM cookies",
 "Web Data": "SELECT name_on_card, expiration_month, card_number_encrypted FROM credit_cards",
 "key4.db": "SELECT item1, item2 FROM metaData WHERE id = 'password'",
 "cookies.sqlite": "SELECT host, name, value FROM moz_cookies",
}
bad = 0
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*"))):
    name = os.path.basename(path).rsplit("-", 1)[0]
    try:
        con = sqlite3.connect("file:" + path.replace(os.sep, "/") + "?mode=ro", uri=True)
        ok = con.execute("PRAGMA integrity_check").fetchall()
        rows = con.execute(queries[name]).fetchall()
        tables = con.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        if ok != [("ok",)] or not rows or any(r[0] is None for r in rows):
            bad += 1
            print("BAD", path, ok, rows[:2])
        else:
            print("ok ", name, os.path.getsize(path), "bytes,", tables, "tables,", len(rows), "rows, e.g.", str(rows[0][:2])[:70])
    except Exception as e:
        bad += 1
        print("BAD", path, repr(e))
sys.exit(1 if bad else 0)
`
	out, err := exec.Command(py, "-c", script, dir).CombinedOutput()
	if strings.Contains(string(out), "No module named") {
		t.Skip("python has no sqlite3")
	}
	t.Logf("\n%s", out)
	if err != nil {
		t.Fatalf("SQLite rejected a fake database: %v", err)
	}
}
