package baits

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Fake browser databases.
//
// A stealer's first look at "Login Data" is the folder listing: its size. An
// empty database is exactly one page, 4096 bytes, on every install, which no
// profile that was ever used has. So these are real SQLite files: the tables
// the browser makes, a few rows in them (sites, user names, encrypted-looking
// passwords and cookies), and a per-install amount of free pages, like a
// database that has seen deletions. Sizes differ from install to install.
//
// The writer below produces only what that needs: tables whose rows fit on
// one page each, no indexes. (Chromium's own tables also carry UNIQUE
// constraints; those would need index pages kept in step with the rows, and
// nothing reading "SELECT … FROM logins" misses them.)

const sqlitePage = 4096

type sqlTable struct {
	name string
	sql  string
	rows [][]any // nil, int / int64, string or []byte per column
}

func sqlVarint(v uint64) []byte {
	if v <= 0x7f {
		return []byte{byte(v)}
	}
	if v > 0x00ffffffffffffff {
		out := make([]byte, 9)
		out[8] = byte(v)
		v >>= 8
		for i := 7; i >= 0; i-- {
			out[i] = byte(v&0x7f) | 0x80
			v >>= 7
		}
		return out
	}
	var tmp []byte
	for v > 0 {
		tmp = append([]byte{byte(v & 0x7f)}, tmp...)
		v >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

// sqlRecord encodes one row in SQLite's record format.
func sqlRecord(vals []any) []byte {
	var types, body []byte
	for _, v := range vals {
		switch x := v.(type) {
		case nil:
			types = append(types, 0)
		case int:
			v = int64(x)
			t, b := sqlInt(int64(x))
			types, body = append(types, t), append(body, b...)
		case int64:
			t, b := sqlInt(x)
			types, body = append(types, t), append(body, b...)
		case string:
			types = append(types, sqlVarint(uint64(len(x)*2+13))...)
			body = append(body, x...)
		case []byte:
			types = append(types, sqlVarint(uint64(len(x)*2+12))...)
			body = append(body, x...)
		default:
			panic(fmt.Sprintf("sqlite: unsupported value %T", v))
		}
	}
	// The header starts with its own length, which includes that length.
	n := len(types) + 1
	if n > 0x7f {
		n++
	}
	return append(append(sqlVarint(uint64(n)), types...), body...)
}

func sqlInt(x int64) (serial byte, body []byte) {
	switch {
	case x == 0:
		return 8, nil
	case x == 1:
		return 9, nil
	case x >= -128 && x <= 127:
		return 1, []byte{byte(x)}
	case x >= -32768 && x <= 32767:
		return 2, []byte{byte(x >> 8), byte(x)}
	case x >= -2147483648 && x <= 2147483647:
		return 4, []byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(x))
	return 6, b
}

// sqlLeaf lays rows out on one table b-tree leaf page. hdr is where the page
// header starts (100 on the first page, after the file header). Rows that
// don't fit are left out.
func sqlLeaf(page []byte, hdr int, rows [][]any) {
	be := binary.BigEndian
	end := len(page)
	ptr := hdr + 8
	n := 0
	for i, row := range rows {
		rec := sqlRecord(row)
		cell := append(append(sqlVarint(uint64(len(rec))), sqlVarint(uint64(i+1))...), rec...)
		if end-len(cell) < ptr+2+16 {
			break
		}
		end -= len(cell)
		copy(page[end:], cell)
		be.PutUint16(page[ptr:], uint16(end))
		ptr += 2
		n++
	}
	page[hdr] = 0x0D // table leaf
	be.PutUint16(page[hdr+3:], uint16(n))
	be.PutUint16(page[hdr+5:], uint16(end))
}

// buildSQLite returns a database with the given tables, followed by free
// pages (what deleting rows leaves behind), which is what makes its size vary.
func buildSQLite(tables []sqlTable, free int) []byte {
	be := binary.BigEndian
	pages := 1 + len(tables)
	if free > 0 {
		pages += 1 + free // a trunk page listing the free ones
	}
	db := make([]byte, pages*sqlitePage)

	var schema [][]any
	for i, t := range tables {
		schema = append(schema, []any{"table", t.name, t.name, i + 2, t.sql})
		sqlLeaf(db[(i+1)*sqlitePage:(i+2)*sqlitePage], 0, t.rows)
	}
	sqlLeaf(db[:sqlitePage], 100, schema)

	copy(db, "SQLite format 3\x00")
	be.PutUint16(db[16:], sqlitePage)
	db[18], db[19] = 1, 1 // rollback journal
	db[21], db[22], db[23] = 64, 32, 32
	change := uint32(3 + rint(400))
	be.PutUint32(db[24:], change)        // file change counter
	be.PutUint32(db[28:], uint32(pages)) // size in pages
	if free > 0 {
		trunk := 2 + len(tables)
		be.PutUint32(db[32:], uint32(trunk))  // first freelist trunk page
		be.PutUint32(db[36:], uint32(1+free)) // freelist pages in total
		tp := db[(trunk-1)*sqlitePage:]
		be.PutUint32(tp[4:], uint32(free))
		for i := 0; i < free; i++ {
			be.PutUint32(tp[8+4*i:], uint32(trunk+1+i))
			// Free pages keep whatever was on them: old rows, to anything looking.
			copy(db[(trunk+i)*sqlitePage:(trunk+i+1)*sqlitePage], randBytes(sqlitePage))
		}
	}
	be.PutUint32(db[40:], uint32(len(tables))) // schema cookie
	be.PutUint32(db[44:], 4)                   // schema format
	be.PutUint32(db[56:], 1)                   // UTF-8
	be.PutUint32(db[92:], change)              // version-valid-for
	be.PutUint32(db[96:], 3046001)             // SQLITE_VERSION_NUMBER
	return db
}

// webkitTime is how Chromium stores times: microseconds since 1601.
func webkitTime(t time.Time) int64 { return t.UnixMicro() + 11644473600*1_000_000 }

// chromeBlob looks like a value Chromium encrypted: "v10", a nonce, ciphertext and a tag.
func chromeBlob(plainLen int) []byte {
	return append([]byte("v10"), randBytes(12+plainLen+16)...)
}

var baitSites = []struct{ host, login string }{
	{"accounts.google.com", "https://accounts.google.com/signin/v2/identifier"},
	{"www.paypal.com", "https://www.paypal.com/signin"},
	{"www.amazon.com", "https://www.amazon.com/ap/signin"},
	{"github.com", "https://github.com/login"},
	{"www.facebook.com", "https://www.facebook.com/login.php"},
	{"login.live.com", "https://login.live.com/login.srf"},
	{"www.netflix.com", "https://www.netflix.com/login"},
	{"discord.com", "https://discord.com/login"},
	{"store.steampowered.com", "https://store.steampowered.com/login/"},
	{"www.binance.com", "https://www.binance.com/en/login"},
	{"www.coinbase.com", "https://www.coinbase.com/signin"},
	{"twitter.com", "https://twitter.com/i/flow/login"},
	{"www.instagram.com", "https://www.instagram.com/accounts/login/"},
	{"www.ebay.com", "https://signin.ebay.com/ws/eBayISAPI.dll"},
	{"www.dropbox.com", "https://www.dropbox.com/login"},
}

// someSites picks n distinct sites.
func someSites(n int) []struct{ host, login string } {
	idx := map[int]bool{}
	var out []struct{ host, login string }
	for len(out) < n && len(out) < len(baitSites) {
		if i := rint(len(baitSites)); !idx[i] {
			idx[i] = true
			out = append(out, baitSites[i])
		}
	}
	return out
}

// cookieDomain is the domain a site's login cookies are set for: ".google.com"
// for accounts.google.com.
func cookieDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		parts = parts[len(parts)-2:]
	}
	return "." + strings.Join(parts, ".")
}

func sqlMeta(version int) sqlTable {
	return sqlTable{name: "meta", sql: "CREATE TABLE meta(key LONGVARCHAR NOT NULL, value LONGVARCHAR)", rows: [][]any{
		{"mmap_status", "-1"}, {"version", fmt.Sprint(version)}, {"last_compatible_version", fmt.Sprint(version - 1)}}}
}

func past(maxDays int) time.Time {
	return time.Now().Add(-time.Duration(1+rint(maxDays*24*60)) * time.Minute)
}

// genLoginData is a Chromium "Login Data": saved logins for a handful of sites.
func genLoginData(g *Gen) []byte {
	logins := sqlTable{name: "logins", sql: "CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, " +
		"username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, " +
		"date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, " +
		"form_data BLOB, display_name VARCHAR, icon_url VARCHAR, federation_url VARCHAR, skip_zero_click INTEGER, generation_upload_status INTEGER, " +
		"possible_username_pairs BLOB, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, moving_blocked_for BLOB, " +
		"date_password_modified INTEGER NOT NULL DEFAULT 0, sender_email VARCHAR, sender_name VARCHAR, date_received INTEGER, " +
		"sharing_notification_displayed INTEGER NOT NULL DEFAULT 0, keychain_identifier BLOB, sender_profile_image_url VARCHAR)"}
	sites := someSites(3 + rint(5))
	for _, s := range sites {
		user := g.Email
		if rint(3) == 0 {
			user = g.User
		}
		created := past(400)
		realm := "https://" + s.host + "/"
		logins.rows = append(logins.rows, []any{s.login, s.login, "email", user, "password", chromeBlob(8 + rint(14)), "", realm,
			webkitTime(created), 0, 0, 0, 1 + rint(40), nil, "", "", "", 0, 0, nil, nil, webkitTime(created.Add(time.Duration(rint(2000)) * time.Hour)),
			nil, webkitTime(created), nil, nil, 0, 0, nil, nil})
	}
	seq := sqlTable{name: "sqlite_sequence", sql: "CREATE TABLE sqlite_sequence(name,seq)", rows: [][]any{{"logins", len(logins.rows) + rint(6)}}}
	stats := sqlTable{name: "stats", sql: "CREATE TABLE stats (origin_domain VARCHAR NOT NULL, username_value VARCHAR, dismissal_count INTEGER, update_time INTEGER NOT NULL)"}
	return buildSQLite([]sqlTable{sqlMeta(40), logins, seq, stats}, 2+rint(14))
}

// genCookies is a Chromium "Cookies" database.
func genCookies(g *Gen) []byte {
	cookies := sqlTable{name: "cookies", sql: "CREATE TABLE cookies(creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, top_frame_site_key TEXT NOT NULL, " +
		"name TEXT NOT NULL, value TEXT NOT NULL, encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, " +
		"is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL, has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL, " +
		"samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL, source_port INTEGER NOT NULL, last_update_utc INTEGER NOT NULL, source_type INTEGER NOT NULL, " +
		"has_cross_site_ancestor INTEGER NOT NULL)"}
	names := []string{"SID", "HSID", "SSID", "session", "sessionid", "auth_token", "csrftoken", "_ga", "remember_me", "LOGIN_INFO", "c_user", "xs"}
	for _, s := range someSites(4 + rint(5)) {
		for i, n := 0, 1+rint(3); i < n; i++ {
			created := past(120)
			host := cookieDomain(s.host)
			cookies.rows = append(cookies.rows, []any{webkitTime(created), host, "", pick(names), "", chromeBlob(20 + rint(60)), "/",
				webkitTime(created.Add(400 * 24 * time.Hour)), 1, rint(2), webkitTime(created.Add(time.Duration(rint(500)) * time.Hour)), 1, 1, 1,
				rint(3) - 1, 2, 443, webkitTime(created), 0, 0})
		}
	}
	return buildSQLite([]sqlTable{sqlMeta(24), cookies}, 3+rint(20))
}

// genWebData is a Chromium "Web Data": autofill entries and a saved card.
func genWebData(g *Gen) []byte {
	autofill := sqlTable{name: "autofill", sql: "CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, " +
		"date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1)"}
	for _, kv := range [][2]string{{"email", g.Email}, {"username", g.User}, {"firstname", g.First}, {"lastname", g.Last}, {"name", g.First + " " + g.Last}} {
		t := past(300).Unix()
		autofill.rows = append(autofill.rows, []any{kv[0], kv[1], strings.ToLower(kv[1]), t, t + int64(rint(5_000_000)), 1 + rint(30)})
	}
	cards := sqlTable{name: "credit_cards", sql: "CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, " +
		"expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, origin VARCHAR DEFAULT '', use_count INTEGER NOT NULL DEFAULT 0, " +
		"use_date INTEGER NOT NULL DEFAULT 0, billing_address_id VARCHAR, nickname VARCHAR)"}
	// (A text PRIMARY KEY would need an index; say so only in the name.)
	cards.sql = strings.Replace(cards.sql, "guid VARCHAR PRIMARY KEY", "guid VARCHAR", 1)
	guid := fmt.Sprintf("%x-%x-%x-%x-%x", randBytes(4), randBytes(2), randBytes(2), randBytes(2), randBytes(6))
	cards.rows = append(cards.rows, []any{guid, g.First + " " + g.Last, 1 + rint(12), time.Now().Year() + 1 + rint(4), chromeBlob(16),
		past(200).Unix(), "https://www.amazon.com/", 1 + rint(9), past(60).Unix(), "", ""})
	keywords := sqlTable{name: "keywords", sql: "CREATE TABLE keywords (id INTEGER PRIMARY KEY, short_name VARCHAR NOT NULL, keyword VARCHAR NOT NULL, " +
		"favicon_url VARCHAR NOT NULL, url VARCHAR NOT NULL, safe_for_autoreplace INTEGER, originating_url VARCHAR, date_created INTEGER DEFAULT 0, usage_count INTEGER DEFAULT 0)",
		rows: [][]any{{nil, "Google", "google.com", "https://www.google.com/favicon.ico", "{google:baseURL}search?q={searchTerms}", 1, "", 0, 0},
			{nil, "Bing", "bing.com", "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico", "https://www.bing.com/search?q={searchTerms}", 1, "", 0, 0}}}
	// An old version, from before the oldest one Chromium still upgrades:
	// should the real browser move into this fake profile, it starts its Web
	// Data afresh. At 130, with only these tables, the upgrade failed and the
	// browser said "Something went wrong when opening your profile". (Stealers
	// read the tables; none checks the version.)
	return buildSQLite([]sqlTable{sqlMeta(78), autofill, cards, keywords}, 4+rint(18))
}

// genKey4 is a Firefox key4.db: the salt and the check value its saved
// passwords are encrypted against, and the key itself.
func genKey4(*Gen) []byte {
	meta := sqlTable{name: "metaData", sql: "CREATE TABLE metaData (id, item1, item2)",
		rows: [][]any{{"password", randBytes(20), append([]byte{0x30, 0x81, 0x80, 0x30, 0x66, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d}, randBytes(115)...)}}}
	priv := sqlTable{name: "nssPrivate", sql: "CREATE TABLE nssPrivate (id INTEGER PRIMARY KEY, a0, a1, a2, a3, a11, a102, a103, a104)",
		rows: [][]any{{nil, []byte{0, 0, 0, 4}, []byte{1}, []byte{0}, nil, append([]byte{0x30, 0x81, 0x90}, randBytes(144)...), randBytes(16), []byte{1}, []byte{1}}}}
	return buildSQLite([]sqlTable{meta, priv}, 60+rint(12)) // the real one is ~290 KB, mostly empty
}

// genMozCookies is a Firefox cookies.sqlite.
func genMozCookies(g *Gen) []byte {
	cookies := sqlTable{name: "moz_cookies", sql: "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, " +
		"host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, " +
		"sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0)"}
	names := []string{"SID", "session", "sessionid", "auth_token", "csrftoken", "remember_me", "c_user"}
	for _, s := range someSites(4 + rint(5)) {
		created := past(120)
		host := cookieDomain(s.host)
		cookies.rows = append(cookies.rows, []any{nil, "", pick(names), base64.RawURLEncoding.EncodeToString(randBytes(24 + rint(40))), host, "/",
			created.Add(400 * 24 * time.Hour).Unix(), created.Add(time.Duration(rint(500)) * time.Hour).UnixMicro(), created.UnixMicro(), 1, rint(2), 0, 0, 0, 2})
	}
	return buildSQLite([]sqlTable{cookies}, 20+rint(100))
}
