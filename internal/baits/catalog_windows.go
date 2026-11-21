package baits

import (
	"os"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

func pf() string   { return env("ProgramW6432", env("ProgramFiles", `C:\Program Files`)) }
func pf86() string { return env("ProgramFiles(x86)", `C:\Program Files (x86)`) }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// adminOnly reports whether path is somewhere only administrators can write
// to (Program Files): what's there was installed, not dropped by a program
// running as you.
func adminOnly(path string) bool {
	return paths.Under(path, pf()) || paths.Under(path, pf86())
}

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
