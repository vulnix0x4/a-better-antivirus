// Package baits defines every bait ABA can plant (plain files and fake
// application data that stealers target), decides which ones fit this PC, and
// creates, checks, retires and removes them.
package baits

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/authenticode"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// Kind of bait.
const (
	KindFile   = "file"   // a tempting document in your folders
	KindDecoy  = "decoy"  // fake data for an app you don't use
	KindCanary = "canary" // credentials that phone home when used
)

// Spec describes one bait in the catalog.
type Spec struct {
	ID          string
	Name        string
	Category    string
	Kind        string
	Description string
	Default     bool   // preselected when available
	Caveat      string // shown for opt-in baits
	// Root is the app's data folder. If it already exists before install, the
	// real app is (or was) installed and this decoy is unavailable.
	Root func(u config.UserInfo) string
	// Markers are globs whose existence means the genuine app is installed.
	Markers   func(u config.UserInfo) []string
	OwnerExes []string // genuine executables (lowercase)
	Signer    string   // substring of the genuine app's signer
	// SharedSDK: the file sits where a vendor SDK's default credential lookup
	// reads on startup, so many legitimate signed apps touch it. Signed,
	// non-script readers are logged but not alerted; everything else trips it.
	SharedSDK bool
	// RequiresAny: this bait lives inside one of these (e.g. MetaMask inside a fake browser).
	RequiresAny []string
	Files       func(u config.UserInfo) []FileSpec
	// Inside and Host make this a bait inside a real app (see embeddedProfile):
	// Inside is the app's data folder it's planted in, Host the app's
	// executable in the places it installs to. It's only available when the
	// app is there, the opposite of a decoy.
	Inside func(u config.UserInfo) string
	Host   func(u config.UserInfo) []string
	// Since is the config version that introduced this bait, when it's newer
	// than the catalog's first version: setup then offers it to installs
	// configured before it existed.
	Since int
}

// FileSpec is one file of a bait.
type FileSpec struct {
	Path  string
	Audit bool // put the read/delete audit rule on it
	Text  bool // human-readable (shown by `bait show`)
	Gen   func(g *Gen) []byte
}

func pf() string   { return env("ProgramW6432", env("ProgramFiles", `C:\Program Files`)) }
func pf86() string { return env("ProgramFiles(x86)", `C:\Program Files (x86)`) }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func j(parts ...string) string { return filepath.Join(parts...) }

// ---- per-install variation ----
//
// ABA is open source, so a stealer can know this catalog by heart. If every
// install used the same file names, skipping "wallet recovery phrase.txt" by
// name would be a one-line bypass. So each install picks its own names from
// pools of what file grabbers look for (pass, seed, wallet, backup, 2fa…):
// to skip the baits a stealer would have to skip everything it came for.
//
// The choice is derived from u.Variant, a random value fixed at install time.
// Installs from before this existed have no Variant and keep their old names.

func variantN(u config.UserInfo, what string, n int) int {
	h := sha256.Sum256([]byte(u.Variant + "|" + what))
	return int(binary.LittleEndian.Uint32(h[:4]) % uint32(n))
}

// vary picks one of pool for this install (the first one without a Variant).
func vary(u config.UserInfo, what string, pool ...string) string {
	if u.Variant == "" {
		return pool[0]
	}
	return pool[variantN(u, what, len(pool))]
}

// varyChars is a per-install string of n characters from alphabet (def
// without a Variant).
func varyChars(u config.UserInfo, what, def string, n int, alphabet string) string {
	if u.Variant == "" {
		return def
	}
	h := sha256.Sum256([]byte(u.Variant + "|" + what))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[int(h[i%len(h)]+byte(i))%len(alphabet)]
	}
	return string(b)
}

func passwordsName(u config.UserInfo, where string) string {
	return vary(u, "passwords-"+where, "passwords.txt", "my passwords.txt", "Passwords.txt", "password list.txt",
		"logins and passwords.txt", "pass.txt", "accounts and passwords.txt", "passwords backup.txt")
}

// ldbName is a LevelDB file name the way real ones look: a six-digit sequence
// number that depends on how long the app has been used.
func ldbName(u config.UserInfo, what, def, ext string) string {
	if u.Variant == "" {
		return def
	}
	return "0000" + varyChars(u, what, "", 2, "0123456789") + ext
}

const metamaskID = "nkbihfbeogaeaoehlefnkodbefgpgknn"

// decoyBrowsers can host fake extension data, in order of preference.
var decoyBrowsers = []string{"vivaldi", "yandex", "brave"}

// BrowserUserData returns a decoy browser's "User Data" folder.
func BrowserUserData(u config.UserInfo, id string) string {
	switch id {
	case "yandex":
		return j(u.LocalAppData, `Yandex\YandexBrowser\User Data`)
	case "brave":
		return j(u.LocalAppData, `BraveSoftware\Brave-Browser\User Data`)
	}
	return j(u.LocalAppData, `Vivaldi\User Data`)
}

// ChooseHost picks the decoy browser that will host dependent baits (MetaMask)
// from the selected IDs. Returns "" if none is selected.
func ChooseHost(selected map[string]bool) string {
	for _, b := range decoyBrowsers {
		if selected[b] {
			return b
		}
	}
	return ""
}

func chromiumFiles(userData string, passwords string) []FileSpec {
	if passwords == "" {
		passwords = "Login Data"
	}
	return []FileSpec{
		{Path: j(userData, "Local State"), Audit: true, Gen: genLocalState},
		{Path: j(userData, "Default", passwords), Audit: true, Gen: genLoginData},
		{Path: j(userData, "Default", "Network", "Cookies"), Audit: true, Gen: genCookies},
		{Path: j(userData, "Default", "Web Data"), Audit: true, Gen: genWebData},
		{Path: j(userData, "Default", "Preferences"), Gen: genPreferences},
	}
}

// ---- baits inside real browsers ----
//
// A decoy is fake data for an app you don't have. A stealer that knows ABA
// can turn that around: check that the app is really installed before
// touching its data, and no decoy is ever opened. So for the browsers you do
// have, ABA plants a fake extra *profile* inside the real one's data: a
// "Profile 23" folder next to "Default". Stealers take every profile folder
// they find (that's how they get people's work and second accounts), and here
// "is the browser installed?" says yes.
//
// The browser itself only opens the profiles listed in its "Local State"
// file, so it never touches this one. If it ever does (you created profiles
// until it reached that number, and it adopted the folder), ABA retires the
// bait like a decoy whose app got installed.

type localState struct {
	Profile struct {
		InfoCache map[string]json.RawMessage `json:"info_cache"`
		Created   int                        `json:"profiles_created"`
	} `json:"profile"`
}

func readLocalState(userData string) (ls localState, ok bool) {
	b, err := os.ReadFile(j(userData, "Local State"))
	if err != nil {
		return ls, false
	}
	return ls, json.Unmarshal(b, &ls) == nil
}

// ProfileFolder is the folder name of an embedded profile bait.
func ProfileFolder(u config.UserInfo, id string) string {
	if f := u.Embedded[id]; f != "" {
		return f
	}
	return fmt.Sprintf("Profile %d", 21+variantN(u, id, 18))
}

// FreeProfile picks a profile folder name the browser isn't using and won't
// get to soon: well past the number of profiles it has ever created.
func FreeProfile(s Spec, u config.UserInfo) string {
	ud := s.Inside(u)
	ls, _ := readLocalState(ud)
	base := ls.Profile.Created + 8
	if base < 12 {
		base = 12
	}
	for try := 0; try < 60; try++ {
		name := fmt.Sprintf("Profile %d", base+rint(20))
		if _, err := os.Stat(j(ud, name)); err == nil {
			continue
		}
		if _, used := ls.Profile.InfoCache[name]; !used {
			return name
		}
	}
	return fmt.Sprintf("Profile %d", base+20+rint(900))
}

// Adopted reports whether the real browser has taken an embedded bait's
// folder as one of its own profiles (it's listed in Local State).
func Adopted(s Spec, u config.UserInfo) bool {
	if s.Inside == nil {
		return false
	}
	ls, ok := readLocalState(s.Inside(u))
	if !ok {
		return false
	}
	_, used := ls.Profile.InfoCache[ProfileFolder(u, s.ID)]
	return used
}

func embeddedProfile(id, browser, exe, signer string, userData func(u config.UserInfo) string, appDirs func(u config.UserInfo) []string) Spec {
	return Spec{
		ID: id, Name: "extra profile inside your " + browser, Category: "Browsers", Kind: KindDecoy, Default: true, Since: 3,
		Description: "A fake profile next to your real ones. Stealers take every profile; " + browser + " never opens this one.",
		OwnerExes:   []string{exe}, Signer: signer,
		Inside: userData,
		Host: func(u config.UserInfo) []string {
			var out []string
			for _, d := range appDirs(u) {
				out = append(out, j(d, exe))
			}
			return out
		},
		Files: func(u config.UserInfo) []FileSpec {
			d := j(userData(u), ProfileFolder(u, id))
			return []FileSpec{
				{Path: j(d, "Login Data"), Audit: true, Gen: genLoginData},
				{Path: j(d, "Network", "Cookies"), Audit: true, Gen: genCookies},
				{Path: j(d, "Web Data"), Audit: true, Gen: genWebData},
				{Path: j(d, "Preferences"), Gen: genPreferences},
			}
		},
	}
}

// Catalog lists every bait, in display order.
var Catalog = []Spec{
	// ---- Files ----
	{
		ID: "home-passwords", Name: "password list in your home folder", Category: "Files", Kind: KindFile, Default: true,
		Description: "Scripts and dev-tool based stealers sweep the home folder.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, passwordsName(u, "home")), Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	},
	{
		ID: "documents-passwords", Name: "password list in Documents", Category: "Files", Kind: KindFile, Default: true,
		Description: "File grabbers sweep Documents for *.txt with names like password/wallet/seed.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Documents, passwordsName(u, "documents")), Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	},
	{
		ID: "desktop-passwords", Name: "password list on the Desktop", Category: "Files", Kind: KindFile, Default: true,
		Description: "The #1 folder file grabbers look in. You'll see it every day: don't open it.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Desktop, passwordsName(u, "desktop")), Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	},
	{
		ID: "seed-phrase", Name: "wallet recovery phrase (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Crypto stealers grep for 'seed', 'wallet', 'recovery'.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "seed", "wallet recovery phrase.txt", "seed phrase.txt", "metamask seed.txt", "crypto wallet seed.txt",
				"ledger recovery phrase.txt", "wallet backup seed.txt")
			return []FileSpec{{Path: j(u.Documents, name), Audit: true, Text: true, Gen: genSeedTxt}}
		},
	},
	{
		ID: "backup-codes", Name: "2FA backup codes (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Backup codes bypass 2FA, so stealers grab them.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "codes", "google backup codes.txt", "2fa backup codes.txt", "backup-codes.txt", "google 2fa codes.txt")
			return []FileSpec{{Path: j(u.Documents, name), Audit: true, Text: true, Gen: genBackupCodes}}
		},
	},
	{
		ID: "keepass", Name: "KeePass database (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Stealers collect *.kdbx files to crack offline.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "kdbx", "Passwords.kdbx", "Database.kdbx", "keepass.kdbx", "Personal.kdbx", "passwords backup.kdbx")
			return []FileSpec{{Path: j(u.Documents, name), Audit: true, Gen: genKdbx}}
		},
	},

	// ---- Browsers you don't use ----
	{
		ID: "brave", Name: "Brave browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies. Nothing legit reads them if you don't use Brave.",
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, `BraveSoftware\Brave-Browser`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `BraveSoftware\Brave-Browser\Application\brave.exe`), j(pf(), `BraveSoftware\Brave-Browser\Application\brave.exe`), j(pf86(), `BraveSoftware\Brave-Browser\Application\brave.exe`)}
		},
		OwnerExes: []string{"brave.exe"}, Signer: "Brave Software",
		Files: func(u config.UserInfo) []FileSpec {
			return chromiumFiles(j(u.LocalAppData, `BraveSoftware\Brave-Browser\User Data`), "")
		},
	},
	{
		ID: "opera", Name: "Opera browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Opera Software`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Programs\Opera\opera.exe`), j(u.LocalAppData, `Programs\Opera\launcher.exe`), j(u.LocalAppData, `Programs\Opera GX\opera.exe`), j(pf(), `Opera\opera.exe`)}
		},
		OwnerExes: []string{"opera.exe", "launcher.exe"}, Signer: "Opera Norway",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `Opera Software\Opera Stable`)
			return []FileSpec{
				{Path: j(d, "Local State"), Audit: true, Gen: genLocalState},
				{Path: j(d, "Default", "Login Data"), Audit: true, Gen: genLoginData},
				{Path: j(d, "Default", "Network", "Cookies"), Audit: true, Gen: genCookies},
			}
		},
	},
	{
		ID: "vivaldi", Name: "Vivaldi browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, `Vivaldi`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Vivaldi\Application\vivaldi.exe`), j(pf(), `Vivaldi\Application\vivaldi.exe`)}
		},
		OwnerExes: []string{"vivaldi.exe"}, Signer: "Vivaldi Technologies",
		Files: func(u config.UserInfo) []FileSpec { return chromiumFiles(j(u.LocalAppData, `Vivaldi\User Data`), "") },
	},
	{
		ID: "yandex", Name: "Yandex browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Yandex's password store is on every stealer's list.",
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, `Yandex`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Yandex\YandexBrowser\Application\browser.exe`)}
		},
		OwnerExes: []string{"browser.exe"}, Signer: "YANDEX",
		Files: func(u config.UserInfo) []FileSpec {
			return chromiumFiles(j(u.LocalAppData, `Yandex\YandexBrowser\User Data`), "Ya Passman Data")
		},
	},
	{
		ID: "firefox", Name: "Firefox profile", Category: "Browsers", Kind: KindDecoy,
		Description: "Fake logins.json + key4.db.",
		Caveat:      "If you install Firefox later it may pick up this fake profile before ABA retires it.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Mozilla\Firefox`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(pf(), `Mozilla Firefox\firefox.exe`), j(pf86(), `Mozilla Firefox\firefox.exe`)}
		},
		OwnerExes: []string{"firefox.exe"}, Signer: "Mozilla",
		Files: func(u config.UserInfo) []FileSpec {
			base := j(u.RoamingAppData, `Mozilla\Firefox`)
			prof := j(base, "Profiles", firefoxProfile(u))
			return []FileSpec{
				{Path: j(base, "profiles.ini"), Gen: func(*Gen) []byte { return genProfilesIni(firefoxProfile(u)) }},
				{Path: j(prof, "logins.json"), Audit: true, Gen: genFirefoxLogins},
				{Path: j(prof, "key4.db"), Audit: true, Gen: genKey4},
				{Path: j(prof, "cookies.sqlite"), Audit: true, Gen: genMozCookies},
			}
		},
	},

	// ---- Browsers you do use: a fake profile inside the real one ----
	embeddedProfile("chrome-profile", "Chrome", "chrome.exe", "Google",
		func(u config.UserInfo) string { return j(u.LocalAppData, `Google\Chrome\User Data`) },
		func(u config.UserInfo) []string {
			return []string{j(pf(), `Google\Chrome\Application`), j(pf86(), `Google\Chrome\Application`), j(u.LocalAppData, `Google\Chrome\Application`)}
		}),
	embeddedProfile("edge-profile", "Edge", "msedge.exe", "Microsoft",
		func(u config.UserInfo) string { return j(u.LocalAppData, `Microsoft\Edge\User Data`) },
		func(u config.UserInfo) []string {
			return []string{j(pf86(), `Microsoft\Edge\Application`), j(pf(), `Microsoft\Edge\Application`)}
		}),
	embeddedProfile("brave-profile", "Brave", "brave.exe", "Brave Software",
		func(u config.UserInfo) string { return j(u.LocalAppData, `BraveSoftware\Brave-Browser\User Data`) },
		func(u config.UserInfo) []string {
			return []string{j(pf(), `BraveSoftware\Brave-Browser\Application`), j(pf86(), `BraveSoftware\Brave-Browser\Application`), j(u.LocalAppData, `BraveSoftware\Brave-Browser\Application`)}
		}),

	// ---- Wallets ----
	{
		ID: "metamask", Name: "MetaMask wallet (inside a fake browser)", Category: "Wallets", Kind: KindDecoy, Default: true,
		RequiresAny: decoyBrowsers,
		Description: "The most targeted wallet extension. Lives inside one of the fake browser profiles.",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(BrowserUserData(u, u.DecoyBrowser), "Default", "Local Extension Settings", metamaskID)
			return []FileSpec{
				{Path: j(d, ldbName(u, "metamask", "000003.log", ".log")), Audit: true, Gen: genMetamaskLog},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
				{Path: j(d, "LOCK"), Gen: func(*Gen) []byte { return nil }},
				{Path: j(d, "MANIFEST-000001"), Gen: genLevelDBManifest},
			}
		},
	},
	{
		ID: "exodus", Name: "Exodus wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake seed.seco + passphrase.json.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Exodus`) },
		Markers:     func(u config.UserInfo) []string { return []string{j(u.LocalAppData, `exodus\Exodus.exe`)} },
		OwnerExes:   []string{"exodus.exe"}, Signer: "Exodus Movement",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `Exodus\exodus.wallet`)
			return []FileSpec{
				{Path: j(d, "seed.seco"), Audit: true, Gen: genSeco},
				{Path: j(d, "passphrase.json"), Audit: true, Gen: genExodusPassphrase},
				{Path: j(d, "info.seco"), Audit: true, Gen: genSeco},
			}
		},
	},
	{
		ID: "electrum", Name: "Electrum wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake default_wallet file.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Electrum`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(pf86(), `Electrum\*.exe`), j(pf(), `Electrum\*.exe`)}
		},
		Signer: "Electrum",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.RoamingAppData, `Electrum\wallets\default_wallet`), Audit: true, Gen: genElectrumWallet}}
		},
	},
	{
		ID: "atomic", Name: "Atomic Wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake wallet storage.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `atomic`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Programs\atomic\Atomic Wallet.exe`)}
		},
		OwnerExes: []string{"atomic wallet.exe"}, Signer: "Atomic",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `atomic\Local Storage\leveldb`)
			return []FileSpec{
				{Path: j(d, ldbName(u, "atomic", "000003.log", ".log")), Audit: true, Gen: genAtomicLog},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
			}
		},
	},

	// ---- Messaging & gaming ----
	{
		ID: "telegram", Name: "Telegram Desktop session", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Stolen tdata = logged-in Telegram account.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `Telegram Desktop`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.RoamingAppData, `Telegram Desktop\Telegram.exe`)}
		},
		OwnerExes: []string{"telegram.exe"}, Signer: "Telegram",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `Telegram Desktop\tdata`)
			return []FileSpec{
				{Path: j(d, "key_datas"), Audit: true, Gen: genTDF},
				{Path: j(d, "D877F783D5D3EF8C", "maps"), Audit: true, Gen: genTDF},
				{Path: j(d, "D877F783D5D3EF8Cs"), Audit: true, Gen: genTDF},
			}
		},
	},
	{
		ID: "discord", Name: "Discord token store", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Token grabbers read Discord's Local Storage.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `discord`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(u.LocalAppData, `Discord\Update.exe`), j(u.LocalAppData, `DiscordPTB\Update.exe`), j(u.LocalAppData, `DiscordCanary\Update.exe`)}
		},
		OwnerExes: []string{"discord.exe", "update.exe"}, Signer: "Discord",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, `discord\Local Storage\leveldb`)
			return []FileSpec{
				{Path: j(d, ldbName(u, "discord", "000005.ldb", ".ldb")), Audit: true, Gen: genDiscordLdb},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
				{Path: j(d, "LOCK"), Gen: func(*Gen) []byte { return nil }},
			}
		},
	},
	{
		ID: "filezilla", Name: "FileZilla saved servers", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Saved FTP/SFTP logins.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, `FileZilla`) },
		Markers: func(u config.UserInfo) []string {
			return []string{j(pf(), `FileZilla FTP Client\filezilla.exe`), j(pf86(), `FileZilla FTP Client\filezilla.exe`)}
		},
		OwnerExes: []string{"filezilla.exe"}, Signer: "Tim Kosse",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "FileZilla")
			return []FileSpec{
				{Path: j(d, "sitemanager.xml"), Audit: true, Text: true, Gen: genSiteManager},
				{Path: j(d, "recentservers.xml"), Audit: true, Text: true, Gen: genRecentServers},
			}
		},
	},

	// ---- Cloud & dev credentials ----
	{
		ID: "aws", Name: "AWS credentials (~/.aws)", Category: "Credentials", Kind: KindCanary, Default: true,
		Description: "With canary tokens on, these keys email you if anyone ever uses them.",
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".aws") },
		Markers:     func(u config.UserInfo) []string { return []string{j(pf(), `Amazon\AWSCLIV2\aws.exe`)} },
		OwnerExes:   []string{"aws.exe"}, Signer: "Amazon",
		// Every AWS SDK looks here on startup (OpenCode, Claude Code, VS Code, Terraform…).
		SharedSDK: true,
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{
				{Path: j(u.Profile, ".aws", "credentials"), Audit: true, Text: true, Gen: genAWSCredentials},
				{Path: j(u.Profile, ".aws", "config"), Text: true, Gen: genAWSConfig},
			}
		},
	},
	{
		ID: "ssh-backup", Name: "Old SSH key backup (~/.ssh)", Category: "Credentials", Kind: KindFile,
		Description: "Grabbers copy the whole .ssh folder.",
		Caveat:      "Goes in your real .ssh folder. ssh never reads this file name, but tools that scan .ssh will trip it.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, ".ssh", "id_rsa_backup_2023"), Audit: true, Gen: genSSHKey}}
		},
	},
}

// ByID finds a spec.
func ByID(id string) (Spec, bool) {
	for _, s := range Catalog {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

// Availability of a bait on this PC.
type Availability struct {
	Spec      Spec
	Available bool
	Reason    string // why not
}

// Plan reports which catalog baits fit this user. alreadyOurs lists bait IDs
// ABA already created (their Root existing is expected, not a real app).
func Plan(u config.UserInfo, alreadyOurs map[string]bool) []Availability {
	var out []Availability
	avail := map[string]bool{}
	for _, s := range Catalog {
		a := Availability{Spec: s, Available: true}
		if s.Markers != nil {
			// A marker that isn't the genuine app doesn't take away a bait that's
			// already planted: planting a fake one is how you'd try to get rid of it.
			if m, genuine := Installed(s, u); m != "" && (genuine || !alreadyOurs[s.ID]) {
				a.Available, a.Reason = false, "you have it installed ("+m+")"
			}
		}
		if s.Inside != nil {
			// Needs the real browser: its program, and data it has actually used.
			_, errData := os.Stat(j(s.Inside(u), "Local State"))
			if firstExisting(s.Host(u)) == "" || errData != nil {
				a.Available, a.Reason = false, "you don't use it"
			}
		}
		if a.Available && s.Root != nil && !alreadyOurs[s.ID] {
			if _, err := os.Stat(s.Root(u)); err == nil {
				a.Available, a.Reason = false, "its data folder already exists (you use or used it)"
			}
		}
		if a.Available && s.Kind == KindFile && !alreadyOurs[s.ID] {
			for _, f := range s.Files(u) {
				if _, err := os.Stat(filepath.Dir(f.Path)); err != nil {
					a.Available, a.Reason = false, "folder "+filepath.Dir(f.Path)+" doesn't exist"
				}
			}
		}
		if a.Available && len(s.RequiresAny) > 0 {
			ok := false
			for _, r := range s.RequiresAny {
				ok = ok || avail[r]
			}
			if !ok {
				a.Available, a.Reason = false, "needs one of the fake browsers ("+strings.Join(s.RequiresAny, ", ")+"), and you use all of them"
			}
		}
		avail[s.ID] = a.Available
		out = append(out, a)
	}
	return out
}

// InstalledMarker returns the first marker that exists (the real app may be installed).
func InstalledMarker(s Spec, u config.UserInfo) string {
	if s.Markers == nil {
		return ""
	}
	return firstExisting(s.Markers(u))
}

// Genuine reports whether the file at path really is the app's executable:
// validly signed by its publisher. A variable so tests can stand in for it.
var Genuine = func(path, signer string) bool {
	r := authenticode.Verify(path)
	return r.Valid && (signer == "" || strings.Contains(strings.ToLower(r.Signer), strings.ToLower(signer)))
}

// Installed looks for the app a decoy imitates. It returns the marker found
// and whether it's genuine.
//
// Most of these apps install into your own profile, where no admin rights are
// needed, so anything running as you can create "Discord\Update.exe" too.
// An empty or unsigned file there isn't the app: it's what a stealer would
// plant to make ABA retire its Discord decoy by itself. Only a file signed by
// the app's publisher counts, or one in Program Files (which takes admin
// rights to write to).
func Installed(s Spec, u config.UserInfo) (marker string, genuine bool) {
	if s.Markers == nil {
		return "", false
	}
	for _, g := range s.Markers(u) {
		var found []string
		if strings.ContainsAny(g, "*?[") {
			found, _ = filepath.Glob(g)
		} else if _, err := os.Stat(g); err == nil {
			found = []string{g}
		}
		for _, m := range found {
			if marker == "" {
				marker = m
			}
			if paths.Under(m, pf()) || paths.Under(m, pf86()) || Genuine(m, s.Signer) {
				return m, true
			}
		}
	}
	return marker, false
}

// OwnerDirs are the folders the genuine app installs into (where its markers
// are): the only places "the real app" can be running from.
func OwnerDirs(s Spec, u config.UserInfo) []string {
	var markers []string
	if s.Markers != nil {
		markers = s.Markers(u)
	}
	if s.Host != nil {
		markers = append(markers, s.Host(u)...)
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range markers {
		d := filepath.Dir(m)
		if strings.ContainsAny(d, "*?[") || seen[strings.ToLower(d)] {
			continue
		}
		seen[strings.ToLower(d)] = true
		out = append(out, d)
	}
	return out
}

func firefoxProfile(u config.UserInfo) string {
	return varyChars(u, "firefox", "q8m3kx2v", 8, "abcdefghijklmnopqrstuvwxyz0123456789") + ".default-release"
}

func firstExisting(globs []string) string {
	for _, g := range globs {
		if strings.ContainsAny(g, "*?[") {
			if m, _ := filepath.Glob(g); len(m) > 0 {
				return m[0]
			}
			continue
		}
		if _, err := os.Stat(g); err == nil {
			return g
		}
	}
	return ""
}

// Categories returns category names in catalog order.
func Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Catalog {
		if !seen[s.Category] {
			seen[s.Category] = true
			out = append(out, s.Category)
		}
	}
	return out
}

// DependentsOf returns IDs that require id.
func DependentsOf(id string) []string {
	var out []string
	for _, s := range Catalog {
		for _, r := range s.RequiresAny {
			if r == id {
				out = append(out, s.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// CustomSpec builds a spec for a user-chosen file (adopted if it exists,
// otherwise filled with a fake passwords list).
func CustomSpec(id, path string) Spec {
	return Spec{
		ID: id, Name: filepath.Base(path) + " (custom)", Category: "Custom", Kind: KindFile,
		Files: func(config.UserInfo) []FileSpec {
			return []FileSpec{{Path: path, Audit: true, Text: true, Gen: genPasswordsTxt}}
		},
	}
}

// SpecFor resolves a configured bait (catalog or custom).
func SpecFor(b config.BaitConfig) (Spec, bool) {
	if b.Path != "" {
		return CustomSpec(b.ID, b.Path), true
	}
	return ByID(b.ID)
}

// SpecByID resolves an ID using the config's custom baits too.
func SpecByID(cfg *config.Config, id string) (Spec, bool) {
	for _, b := range cfg.Baits {
		if b.ID == id {
			return SpecFor(b)
		}
	}
	return ByID(id)
}

// Moved reports whether a planted bait's files are no longer where its spec
// puts them for u (the install was given new bait names).
func Moved(bs *config.BaitState, s Spec, u config.UserInfo) bool {
	want := s.Files(u)
	if len(want) != len(bs.Files) {
		return true
	}
	have := map[string]bool{}
	for _, f := range bs.Files {
		have[paths.Key(f.Path)] = true
	}
	for _, f := range want {
		if !have[paths.Key(f.Path)] {
			return true
		}
	}
	return false
}
