package baits

// The baits for Linux: a starter set, chosen for what Linux stealers and
// malicious npm and PyPI packages go after.
//
// Two rules decided what's in it:
//
//   - Never fake a file that real tools look for by themselves. ~/.aws/
//     credentials, ~/.npmrc, ~/.netrc, ~/.kube/config and Google's
//     application_default_credentials.json are read by every SDK and
//     command-line tool on start-up, whether or not you use that service: a
//     fake one would trip all day, and worse, the tools would use the fake
//     credentials. So the credential baits are files only a stealer (or the
//     one tool they belong to, when it isn't installed) ever opens: a spare
//     SSH key under a name ssh never tries, a backup copy of the AWS
//     credentials, ~/.git-credentials where git isn't set up to use it, the
//     gcloud command's own token databases.
//   - A decoy is only planted for an app that isn't there (its data folder
//     doesn't exist, its program isn't installed), and a fake profile only
//     inside a browser that is.

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

// adminOnly reports whether path is somewhere only root can write to: what's
// there was installed, not dropped by a program running as you.
func adminOnly(path string) bool {
	ok, _ := provenance.RootOnly(path)
	return ok
}

// BrowserUserData returns a decoy browser's data folder (~/.config/…).
func BrowserUserData(u config.UserInfo, id string) string {
	switch id {
	case "yandex":
		return j(u.RoamingAppData, "yandex-browser")
	case "brave":
		return j(u.RoamingAppData, "BraveSoftware", "Brave-Browser")
	}
	return j(u.RoamingAppData, "vivaldi")
}

// lf gives a text bait Linux line endings.
func lf(gen func(*Gen) []byte) func(*Gen) []byte {
	return func(g *Gen) []byte { return bytes.ReplaceAll(gen(g), []byte("\r\n"), []byte("\n")) }
}

// linuxChromium is a Chromium-family profile the way it looks on Linux.
func linuxChromium(userData string) []FileSpec {
	return []FileSpec{
		{Path: j(userData, "Local State"), Audit: true, Gen: genLocalState},
		{Path: j(userData, "Default", "Login Data"), Audit: true, Gen: genLoginData},
		{Path: j(userData, "Default", "Cookies"), Audit: true, Gen: genCookies},
		{Path: j(userData, "Default", "Web Data"), Audit: true, Gen: genWebData},
		{Path: j(userData, "Default", "Preferences"), Gen: genPreferences},
	}
}

// programs lists a program under the names and folders distributions and
// vendors install it to.
func programs(names ...string) []string {
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "/") {
			out = append(out, n)
			continue
		}
		out = append(out, "/usr/bin/"+n, "/usr/local/bin/"+n, "/snap/bin/"+n)
	}
	return out
}

func genGitCredentials(g *Gen) []byte {
	host := strings.ToLower(g.Last) + "-consulting"
	return []byte(fmt.Sprintf("https://%s:glpat-%s@gitlab.%s.internal\nhttps://deploy:%s@git.%s.internal\n",
		g.User, randAlnum(20, alnum), host, randAlnum(40, "0123456789abcdef"), host))
}

func genAWSBackup(g *Gen) []byte {
	return bytes.ReplaceAll(genAWSCredentials(g), []byte("\r\n"), []byte("\n"))
}

func gcloudAccount(g *Gen) string { return g.Email }

func genGcloudCredentials(g *Gen) []byte {
	value := fmt.Sprintf(`{"client_id": "32555940559.apps.googleusercontent.com", "client_secret": "%s", "refresh_token": "1//0%s", "type": "authorized_user", "universe_domain": "googleapis.com"}`,
		randAlnum(24, alnum+"-_"), randAlnum(100, alnum+"-_"))
	return buildSQLite([]sqlTable{{
		name: "credentials", sql: "CREATE TABLE credentials (account_id TEXT PRIMARY KEY, value BLOB)",
		rows: [][]any{{gcloudAccount(g), value}},
	}}, 1+rint(3))
}

func genGcloudTokens(g *Gen) []byte {
	return buildSQLite([]sqlTable{{
		name: "access_tokens",
		sql:  "CREATE TABLE access_tokens (account_id TEXT PRIMARY KEY, access_token TEXT, token_expiry TIMESTAMP, rapt_token TEXT, id_token TEXT)",
		rows: [][]any{{gcloudAccount(g), "ya29.a0" + randAlnum(180, alnum+"-_"), past(30).UTC().Format("2006-01-02 15:04:05.000000"), nil, nil}},
	}}, 1+rint(3))
}

func genGcloudADC(g *Gen) []byte {
	return []byte(fmt.Sprintf("{\n  \"client_id\": \"32555940559.apps.googleusercontent.com\",\n  \"client_secret\": \"%s\",\n  \"refresh_token\": \"1//0%s\",\n  \"type\": \"authorized_user\"\n}\n",
		randAlnum(24, alnum+"-_"), randAlnum(100, alnum+"-_")))
}

// Catalog lists every bait, in display order.
var Catalog = []Spec{
	// ---- Files ----
	{
		ID: "home-passwords", Name: "password list in your home folder", Category: "Files", Kind: KindFile, Default: true,
		Description: "Scripts and package-based stealers sweep the home folder.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, passwordsName(u, "home")), Audit: true, Text: true, Gen: lf(genPasswordsTxt)}}
		},
	},
	{
		ID: "documents-passwords", Name: "password list in Documents", Category: "Files", Kind: KindFile, Default: true,
		Description: "File grabbers sweep Documents for *.txt with names like password/wallet/seed.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Documents, passwordsName(u, "documents")), Audit: true, Text: true, Gen: lf(genPasswordsTxt)}}
		},
	},
	{
		ID: "seed-phrase", Name: "wallet recovery phrase (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Crypto stealers grep for 'seed', 'wallet', 'recovery'.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "seed", "wallet recovery phrase.txt", "seed phrase.txt", "metamask seed.txt", "crypto wallet seed.txt",
				"ledger recovery phrase.txt", "wallet backup seed.txt")
			return []FileSpec{{Path: j(u.Documents, name), Audit: true, Text: true, Gen: lf(genSeedTxt)}}
		},
	},
	{
		ID: "desktop-passwords", Name: "password list on the Desktop", Category: "Files", Kind: KindFile, Default: true,
		Description: "The first folder file grabbers look in. You'll see it every day: don't open it.",
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Desktop, passwordsName(u, "desktop")), Audit: true, Text: true, Gen: lf(genPasswordsTxt)}}
		},
	},
	{
		ID: "backup-codes", Name: "2FA backup codes (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Backup codes bypass 2FA, so stealers grab them.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "codes", "google backup codes.txt", "2fa backup codes.txt", "backup-codes.txt", "google 2fa codes.txt")
			return []FileSpec{{Path: j(u.Documents, name), Audit: true, Text: true, Gen: lf(genBackupCodes)}}
		},
	},
	{
		ID: "keepass", Name: "KeePass database (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Stealers collect *.kdbx files to crack offline. KeePassXC only opens the databases you open.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "kdbx", "Passwords.kdbx", "Database.kdbx", "keepass.kdbx", "Personal.kdbx", "passwords backup.kdbx")
			return []FileSpec{{Path: j(u.Documents, name), Audit: true, Gen: genKdbx}}
		},
	},

	// ---- Browsers you don't use ----
	{
		ID: "vivaldi", Name: "Vivaldi browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies. Nothing legit reads them if you don't use Vivaldi.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "vivaldi") },
		Markers: func(u config.UserInfo) []string {
			return programs("vivaldi", "vivaldi-stable", "/opt/vivaldi/vivaldi", "/var/lib/flatpak/app/com.vivaldi.Vivaldi")
		},
		OwnerExes: []string{"vivaldi-bin", "vivaldi"}, Signer: "vivaldi",
		Files: func(u config.UserInfo) []FileSpec { return linuxChromium(j(u.RoamingAppData, "vivaldi")) },
	},
	{
		ID: "brave", Name: "Brave browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "BraveSoftware") },
		Markers: func(u config.UserInfo) []string {
			return programs("brave-browser", "brave-browser-stable", "brave", "/opt/brave.com/brave/brave", "/var/lib/flatpak/app/com.brave.Browser")
		},
		OwnerExes: []string{"brave"}, Signer: "brave",
		Files: func(u config.UserInfo) []FileSpec {
			return linuxChromium(j(u.RoamingAppData, "BraveSoftware", "Brave-Browser"))
		},
	},

	{
		ID: "opera", Name: "Opera browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "opera") },
		Markers: func(u config.UserInfo) []string {
			return programs("opera", "opera-stable", "/usr/lib/x86_64-linux-gnu/opera/opera", "/usr/lib/aarch64-linux-gnu/opera/opera", "/var/lib/flatpak/app/com.opera.Opera")
		},
		OwnerExes: []string{"opera"}, Signer: "opera",
		Files: func(u config.UserInfo) []FileSpec {
			// Opera keeps its one profile right in its data folder.
			d := j(u.RoamingAppData, "opera")
			return []FileSpec{
				{Path: j(d, "Local State"), Audit: true, Gen: genLocalState},
				{Path: j(d, "Login Data"), Audit: true, Gen: genLoginData},
				{Path: j(d, "Cookies"), Audit: true, Gen: genCookies},
			}
		},
	},
	{
		ID: "yandex", Name: "Yandex browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Yandex's password store is on every stealer's list.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "yandex-browser") },
		Markers: func(u config.UserInfo) []string {
			return programs("yandex-browser", "yandex-browser-stable", "/opt/yandex/browser/yandex_browser", "/opt/yandex/browser/yandex-browser")
		},
		OwnerExes: []string{"yandex_browser", "yandex-browser"}, Signer: "yandex",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "yandex-browser")
			return []FileSpec{
				{Path: j(d, "Local State"), Audit: true, Gen: genLocalState},
				{Path: j(d, "Default", "Ya Passman Data"), Audit: true, Gen: genLoginData},
				{Path: j(d, "Default", "Cookies"), Audit: true, Gen: genCookies},
				{Path: j(d, "Default", "Preferences"), Gen: genPreferences},
			}
		},
	},
	{
		ID: "firefox", Name: "Firefox profile", Category: "Browsers", Kind: KindDecoy,
		Description: "Fake logins.json + key4.db, for a machine without Firefox.",
		Caveat:      "If you install Firefox later it may pick up this fake profile before ABA retires it.",
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".mozilla", "firefox") },
		Markers:     func(u config.UserInfo) []string { return firefoxHosts(u) },
		OwnerExes:   []string{"firefox", "firefox-bin", "firefox-esr"}, Signer: "firefox",
		Files: func(u config.UserInfo) []FileSpec {
			base := j(u.Profile, ".mozilla", "firefox")
			prof := j(base, firefoxProfile(u))
			return []FileSpec{
				{Path: j(base, "profiles.ini"), Gen: func(*Gen) []byte {
					return bytes.ReplaceAll(bytes.ReplaceAll(genProfilesIni(firefoxProfile(u)), []byte("Path=Profiles/"), []byte("Path=")), []byte("\r\n"), []byte("\n"))
				}},
				{Path: j(prof, "logins.json"), Audit: true, Gen: genFirefoxLogins},
				{Path: j(prof, "key4.db"), Audit: true, Gen: genKey4},
				{Path: j(prof, "cookies.sqlite"), Audit: true, Gen: genMozCookies},
			}
		},
	},

	// ---- Browsers you do use: a fake profile inside the real one ----
	// Firefox: Ubuntu's comes as a snap, others as a package or a flatpak, each
	// with its data in its own place.
	embeddedFirefox("firefox-profile", "Firefox", "firefox",
		func(u config.UserInfo) string { return j(u.Profile, ".mozilla", "firefox") },
		func(u config.UserInfo) []string {
			return []string{"/usr/lib/firefox/firefox", "/usr/lib64/firefox/firefox", "/usr/lib/firefox-esr/firefox-esr", "/opt/firefox/firefox"}
		}),
	embeddedFirefox("firefox-snap-profile", "Firefox (snap)", "firefox",
		func(u config.UserInfo) string {
			return j(u.Profile, "snap", "firefox", "common", ".mozilla", "firefox")
		},
		func(u config.UserInfo) []string { return []string{"/snap/firefox/current/usr/lib/firefox/firefox"} }),
	embeddedFirefox("firefox-flatpak-profile", "Firefox (flatpak)", "org.mozilla.firefox",
		func(u config.UserInfo) string {
			return j(u.Profile, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox")
		},
		func(u config.UserInfo) []string {
			return []string{"/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib/firefox/firefox"}
		}),
	embeddedProfile("chrome-profile", "Chrome", "chrome", "google-chrome",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "google-chrome") },
		func(u config.UserInfo) []string { return []string{"/opt/google/chrome"} }),
	embeddedProfile("chromium-profile", "Chromium", "chromium", "chromium",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "chromium") },
		func(u config.UserInfo) []string { return []string{"/usr/lib/chromium", "/usr/lib64/chromium"} }),
	embeddedProfile("chromium-snap-profile", "Chromium (snap)", "chrome", "chromium",
		func(u config.UserInfo) string { return j(u.Profile, "snap", "chromium", "common", "chromium") },
		func(u config.UserInfo) []string { return []string{"/snap/chromium/current/usr/lib/chromium-browser"} }),
	embeddedProfile("brave-profile", "Brave", "brave", "brave",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "BraveSoftware", "Brave-Browser") },
		func(u config.UserInfo) []string { return []string{"/opt/brave.com/brave"} }),
	embeddedProfile("edge-profile", "Edge", "msedge", "microsoft-edge",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "microsoft-edge") },
		func(u config.UserInfo) []string { return []string{"/opt/microsoft/msedge"} }),

	// ---- Wallets ----
	{
		ID: "electrum", Name: "Electrum wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake default_wallet file, where every wallet stealer looks.",
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".electrum") },
		Markers:     func(u config.UserInfo) []string { return programs("electrum") },
		Signer:      "electrum",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.Profile, ".electrum")
			return []FileSpec{
				{Path: j(d, "wallets", "default_wallet"), Audit: true, Gen: genElectrumWallet},
				{Path: j(d, "config"), Gen: func(*Gen) []byte {
					return []byte("{\n    \"auto_connect\": true,\n    \"check_updates\": false,\n    \"config_version\": 3,\n    \"decimal_point\": 8,\n    \"is_maximized\": false,\n    \"oneserver\": false\n}")
				}},
			}
		},
	},

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
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "Exodus") },
		Markers: func(u config.UserInfo) []string {
			return programs("exodus", "/opt/exodus/Exodus", "/opt/Exodus/Exodus", "/var/lib/flatpak/app/io.exodus.Exodus")
		},
		OwnerExes: []string{"exodus"}, Signer: "exodus",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "Exodus", "exodus.wallet")
			return []FileSpec{
				{Path: j(d, "seed.seco"), Audit: true, Gen: genSeco},
				{Path: j(d, "passphrase.json"), Audit: true, Gen: genExodusPassphrase},
				{Path: j(d, "info.seco"), Audit: true, Gen: genSeco},
			}
		},
	},
	{
		ID: "atomic", Name: "Atomic Wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake wallet storage.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "atomic") },
		Markers: func(u config.UserInfo) []string {
			return programs("atomic", "/opt/Atomic Wallet/atomic", "/var/lib/flatpak/app/io.atomicwallet.AtomicWallet")
		},
		OwnerExes: []string{"atomic"}, Signer: "atomic",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "atomic", "Local Storage", "leveldb")
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
		Root:        func(u config.UserInfo) string { return j(u.LocalAppData, "TelegramDesktop") },
		Markers: func(u config.UserInfo) []string {
			return programs("telegram-desktop", "Telegram", "/opt/telegram/Telegram", "/var/lib/flatpak/app/org.telegram.desktop")
		},
		OwnerExes: []string{"telegram-desktop", "telegram"}, Signer: "telegram",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.LocalAppData, "TelegramDesktop", "tdata")
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
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "discord") },
		Markers: func(u config.UserInfo) []string {
			return programs("discord", "/usr/share/discord/Discord", "/opt/discord/Discord", "/opt/Discord/Discord", "/var/lib/flatpak/app/com.discordapp.Discord")
		},
		OwnerExes: []string{"discord"}, Signer: "discord",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "discord", "Local Storage", "leveldb")
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
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "filezilla") },
		Markers: func(u config.UserInfo) []string {
			return programs("filezilla", "/var/lib/flatpak/app/org.filezillaproject.Filezilla")
		},
		OwnerExes: []string{"filezilla"}, Signer: "filezilla",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "filezilla")
			return []FileSpec{
				{Path: j(d, "sitemanager.xml"), Audit: true, Text: true, Gen: lf(genSiteManager)},
				{Path: j(d, "recentservers.xml"), Audit: true, Text: true, Gen: lf(genRecentServers)},
			}
		},
	},

	// ---- Developer credentials ----
	{
		ID: "ssh-key", Name: "spare SSH key (~/.ssh)", Category: "Credentials", Kind: KindDecoy, Default: true,
		Description: "A private key under a name ssh never tries by itself. Grabbers copy every key in .ssh.",
		Files: func(u config.UserInfo) []FileSpec {
			// No .pub next to it: the desktop keyring loads the keys it finds a
			// public half for.
			name := vary(u, "ssh", "id_rsa.bak", "id_rsa.old", "id_rsa_backup", "id_rsa.orig", "old_id_rsa", "id_rsa_work", "id_rsa.save")
			return []FileSpec{{Path: j(u.Profile, ".ssh", name), Audit: true, Gen: genSSHKey}}
		},
	},
	{
		ID: "git-credentials", Name: "saved git passwords (~/.git-credentials)", Category: "Credentials", Kind: KindDecoy, Default: true,
		Description: "Where git keeps passwords in plain text when told to. Yours doesn't use it; stealers always look.",
		// The file itself stands for "the app": if it's there, git's store is in use.
		Root: func(u config.UserInfo) string { return j(u.Profile, ".git-credentials") },
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, ".git-credentials"), Audit: true, Text: true, Gen: genGitCredentials}}
		},
	},
	{
		ID: "aws", Name: "AWS credentials backup (~/.aws)", Category: "Credentials", Kind: KindCanary, Default: true,
		Description: "A backup copy of AWS keys, which no AWS tool reads. With canary tokens on, the keys email you if anyone ever uses them.",
		Files: func(u config.UserInfo) []FileSpec {
			name := vary(u, "aws", "credentials.bak", "credentials.old", "credentials.backup", "credentials.orig", "credentials~", "credentials.save")
			return []FileSpec{{Path: j(u.Profile, ".aws", name), Audit: true, Text: true, Gen: genAWSBackup}}
		},
	},
	{
		ID: "gcloud", Name: "Google Cloud login (~/.config/gcloud)", Category: "Credentials", Kind: KindDecoy, Default: true,
		Description: "The gcloud command's own token databases. Only gcloud reads them, and you don't have it.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "gcloud") },
		Markers: func(u config.UserInfo) []string {
			return programs("gcloud", "/usr/lib/google-cloud-sdk/bin/gcloud", "/opt/google-cloud-sdk/bin/gcloud", "/usr/share/google-cloud-sdk/bin/gcloud")
		},
		Signer: "google-cloud",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "gcloud")
			return []FileSpec{
				{Path: j(d, "credentials.db"), Audit: true, Gen: genGcloudCredentials},
				{Path: j(d, "access_tokens.db"), Audit: true, Gen: genGcloudTokens},
				// (Not application_default_credentials.json: every Google SDK reads that one.)
				{Path: j(d, "legacy_credentials", "account", "adc.json"), Audit: true, Text: true, Gen: genGcloudADC},
			}
		},
	},
}

// firefoxHosts are the places a Firefox installs to: the distribution's
// package, Mozilla's tarball, the snap (Ubuntu's, with /usr/bin/firefox as the
// way to it) and the flatpak. (Only where root installs: a folder of yours
// appearing proves nothing, and retiring a decoy for it is what a stealer
// would want.)
func firefoxHosts(u config.UserInfo) []string {
	return append(programs("firefox", "firefox-esr", "/usr/lib/firefox/firefox", "/usr/lib64/firefox/firefox", "/usr/lib/firefox-esr/firefox-esr", "/opt/firefox/firefox"),
		"/snap/firefox/current/usr/lib/firefox/firefox", "/var/lib/flatpak/app/org.mozilla.firefox")
}
