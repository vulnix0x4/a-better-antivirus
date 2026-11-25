package baits

// The baits for macOS: what macOS stealers (Atomic, Banshee, Poseidon,
// Cthulhu…) go after, in the places Mac apps keep it.
//
// The rules are Linux's: never fake a file real tools look for by themselves
// (~/.aws/credentials, ~/.npmrc, ~/.kube/config…), and plant a decoy only for
// an app that isn't there, a fake profile only inside a browser that is.
//
// Two more for the Mac:
//
//   - The app data baits are all under ~/Library/Application Support or in
//     dot-folders of the home folder. Measured over 45 minutes on a Mac in
//     use, nothing read the fake app data there except Spotlight, once, when
//     it was created (and Spotlight is never reported).
//   - Stealers sweep Desktop and Documents too (Atomic has Finder copy
//     documents from both), so there are baits there. When iCloud Drive
//     keeps those folders in sync, a bait there is uploaded and shows up on
//     your iPhone and other Macs: setup says so and asks (yes by default).

import (
	"bytes"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
	"golang.org/x/sys/unix"
)

// adminOnly reports whether path is somewhere only root can write to: what's
// there was installed, not dropped by a program running as you.
func adminOnly(path string) bool {
	ok, _ := provenance.RootOnly(path)
	return ok
}

// inICloud reports whether iCloud Drive keeps dir in sync: macOS marks the
// folder itself when "Desktop & Documents Folders" is on. (Only the folder's
// own attributes are read, never what's in it.)
func inICloud(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := unix.Getxattr(dir, "com.apple.file-provider-domain-id", nil)
	return err == nil
}

// syncedIn is a Spec.Synced for a bait planted in dir(u).
func syncedIn(dir func(u config.UserInfo) string) func(u config.UserInfo) string {
	return func(u config.UserInfo) string {
		if inICloud(dir(u)) {
			return "iCloud Drive keeps your Desktop and Documents in sync, so these decoys will be uploaded to iCloud and show up on your other Apple devices."
		}
		return ""
	}
}

func desktopOf(u config.UserInfo) string   { return u.Desktop }
func documentsOf(u config.UserInfo) string { return u.Documents }

// BrowserUserData returns a decoy browser's data folder.
func BrowserUserData(u config.UserInfo, id string) string {
	switch id {
	case "yandex":
		return j(u.RoamingAppData, "Yandex", "YandexBrowser")
	case "brave":
		return j(u.RoamingAppData, "BraveSoftware", "Brave-Browser")
	}
	return j(u.RoamingAppData, "Vivaldi")
}

// lf gives a text bait Unix line endings.
func lf(gen func(*Gen) []byte) func(*Gen) []byte {
	return func(g *Gen) []byte { return bytes.ReplaceAll(gen(g), []byte("\r\n"), []byte("\n")) }
}

// apps lists an app under the places Mac apps are installed to.
func apps(u config.UserInfo, names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, "/Applications/"+n+".app", j(u.Profile, "Applications", n+".app"))
	}
	return out
}

// macChromium is a Chromium-family profile the way it looks on a Mac.
func macChromium(userData string) []FileSpec {
	return []FileSpec{
		{Path: j(userData, "Local State"), Audit: true, Gen: genLocalState},
		{Path: j(userData, "Default", "Login Data"), Audit: true, Gen: genLoginData},
		{Path: j(userData, "Default", "Cookies"), Audit: true, Gen: genCookies},
		{Path: j(userData, "Default", "Web Data"), Audit: true, Gen: genWebData},
		{Path: j(userData, "Default", "Preferences"), Gen: genPreferences},
	}
}

// appBinaryDirs is where a Mac app's programs are, for an app called name.
func appBinaryDirs(name string) func(u config.UserInfo) []string {
	return func(u config.UserInfo) []string {
		return []string{"/Applications/" + name + ".app/Contents/MacOS", j(u.Profile, "Applications", name+".app", "Contents", "MacOS")}
	}
}

func genAWSBackup(g *Gen) []byte {
	return bytes.ReplaceAll(genAWSCredentials(g), []byte("\r\n"), []byte("\n"))
}

// Catalog lists every bait, in display order.
var Catalog = []Spec{
	// ---- Files ----
	{
		ID: "home-passwords", Name: "password list in your home folder", Category: "Files", Kind: KindFile, Default: true,
		Description: "Stealers and malicious scripts sweep the home folder.",
		Files: func(u config.UserInfo) []FileSpec {
			name, alt := passwordsName(u, "home")
			return []FileSpec{{Path: j(u.Profile, name), Alt: alt, Audit: true, Text: true, Gen: lf(genPasswordsTxt)}}
		},
	},
	{
		ID: "documents-passwords", Name: "password list in Documents", Category: "Files", Kind: KindFile, Default: true,
		Description: "Atomic and its kin have Finder copy documents with names like password, wallet, seed.",
		Synced:      syncedIn(documentsOf),
		Files: func(u config.UserInfo) []FileSpec {
			name, alt := passwordsName(u, "documents")
			return []FileSpec{{Path: j(u.Documents, name), Alt: alt, Audit: true, Text: true, Gen: lf(genPasswordsTxt)}}
		},
	},
	{
		ID: "desktop-passwords", Name: "password list on the Desktop", Category: "Files", Kind: KindFile, Default: true,
		Description: "The Desktop is the first folder file grabbers sweep.",
		Synced:      syncedIn(desktopOf),
		Files: func(u config.UserInfo) []FileSpec {
			name, alt := passwordsName(u, "desktop")
			return []FileSpec{{Path: j(u.Desktop, name), Alt: alt, Audit: true, Text: true, Gen: lf(genPasswordsTxt)}}
		},
	},
	{
		ID: "seed-phrase", Name: "wallet recovery phrase (Documents)", Category: "Files", Kind: KindFile, Default: true,
		Description: "Crypto stealers look for 'seed', 'wallet', 'recovery'.",
		Synced:      syncedIn(documentsOf),
		Files: func(u config.UserInfo) []FileSpec {
			name, alt := varyFile(u, "seed", "wallet recovery phrase.txt", "seed phrase.txt", "metamask seed.txt", "crypto wallet seed.txt",
				"ledger recovery phrase.txt", "wallet backup seed.txt")
			return []FileSpec{{Path: j(u.Documents, name), Alt: alt, Audit: true, Text: true, Gen: lf(genSeedTxt)}}
		},
	},

	// ---- Browsers you don't use ----
	{
		ID: "vivaldi", Name: "Vivaldi browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies. Nothing legit reads them if you don't use Vivaldi.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "Vivaldi") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "Vivaldi") },
		OwnerExes:   []string{"vivaldi"}, Signer: "Vivaldi",
		Files: func(u config.UserInfo) []FileSpec { return macChromium(j(u.RoamingAppData, "Vivaldi")) },
	},
	{
		ID: "yandex", Name: "Yandex browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies. A favourite of stealers sold in Russian-speaking markets.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "Yandex") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "Yandex") },
		OwnerExes:   []string{"yandex"}, Signer: "Yandex",
		Files: func(u config.UserInfo) []FileSpec { return macChromium(j(u.RoamingAppData, "Yandex", "YandexBrowser")) },
	},
	{
		ID: "brave", Name: "Brave browser profile", Category: "Browsers", Kind: KindDecoy, Default: true,
		Description: "Fake saved passwords + cookies.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "BraveSoftware") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "Brave Browser") },
		OwnerExes:   []string{"brave browser"}, Signer: "Brave Software",
		Files: func(u config.UserInfo) []FileSpec {
			return macChromium(j(u.RoamingAppData, "BraveSoftware", "Brave-Browser"))
		},
	},

	// ---- Browsers you do use: a fake profile inside the real one ----
	embeddedProfile("chrome-profile", "Chrome", "Google Chrome", "Google LLC",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "Google", "Chrome") }, appBinaryDirs("Google Chrome")),
	embeddedProfile("brave-profile", "Brave", "Brave Browser", "Brave Software",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "BraveSoftware", "Brave-Browser") }, appBinaryDirs("Brave Browser")),
	embeddedProfile("edge-profile", "Edge", "Microsoft Edge", "Microsoft Corporation",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "Microsoft Edge") }, appBinaryDirs("Microsoft Edge")),
	embeddedProfile("vivaldi-profile", "Vivaldi", "Vivaldi", "Vivaldi",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "Vivaldi") }, appBinaryDirs("Vivaldi")),
	embeddedProfile("arc-profile", "Arc", "Arc", "The Browser Company",
		func(u config.UserInfo) string { return j(u.RoamingAppData, "Arc", "User Data") }, appBinaryDirs("Arc")),
	embeddedFirefox("firefox-profile", "Firefox", "Mozilla", 4,
		func(u config.UserInfo) string { return j(u.RoamingAppData, "Firefox") }, "Profiles",
		func(u config.UserInfo) []string {
			return []string{"/Applications/Firefox.app/Contents/MacOS/firefox", j(u.Profile, "Applications", "Firefox.app", "Contents", "MacOS", "firefox")}
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
		Description: "Fake seed.seco + passphrase.json, where every Mac stealer looks.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "Exodus") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "Exodus") },
		OwnerExes:   []string{"exodus"}, Signer: "Exodus Movement",
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
		Markers:     func(u config.UserInfo) []string { return apps(u, "Atomic Wallet") },
		OwnerExes:   []string{"atomic wallet"}, Signer: "Atomic",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "atomic", "Local Storage", "leveldb")
			return []FileSpec{
				{Path: j(d, ldbName(u, "atomic", "000003.log", ".log")), Audit: true, Gen: genAtomicLog},
				{Path: j(d, "CURRENT"), Audit: true, Gen: func(*Gen) []byte { return []byte("MANIFEST-000001\n") }},
			}
		},
	},
	{
		ID: "electrum", Name: "Electrum wallet", Category: "Wallets", Kind: KindDecoy, Default: true,
		Description: "Fake default_wallet file, where every wallet stealer looks.",
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".electrum") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "Electrum") },
		OwnerExes:   []string{"electrum", "run_electrum"}, Signer: "Electrum",
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

	// ---- Apps ----
	{
		ID: "telegram", Name: "Telegram Desktop session", Category: "Apps", Kind: KindDecoy, Default: true,
		Description: "Stolen tdata = logged-in Telegram account.",
		Root:        func(u config.UserInfo) string { return j(u.RoamingAppData, "Telegram Desktop") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "Telegram Desktop") },
		OwnerExes:   []string{"telegram"}, Signer: "Telegram",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.RoamingAppData, "Telegram Desktop", "tdata")
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
		Markers:     func(u config.UserInfo) []string { return apps(u, "Discord", "Discord PTB", "Discord Canary") },
		OwnerExes:   []string{"discord", "discord helper"}, Signer: "Discord",
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
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".config", "filezilla") },
		Markers:     func(u config.UserInfo) []string { return apps(u, "FileZilla") },
		OwnerExes:   []string{"filezilla"}, Signer: "Tim Kosse",
		Files: func(u config.UserInfo) []FileSpec {
			d := j(u.Profile, ".config", "filezilla")
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
			name, alt := varyFile(u, "ssh", "id_rsa.bak", "id_rsa.old", "id_rsa_backup", "id_rsa.orig", "old_id_rsa", "id_rsa_work", "id_rsa.save")
			return []FileSpec{{Path: j(u.Profile, ".ssh", name), Alt: alt, Audit: true, Gen: genSSHKey}}
		},
	},
	{
		ID: "git-credentials", Name: "saved git passwords (~/.git-credentials)", Category: "Credentials", Kind: KindDecoy, Default: true,
		Description: "Where git keeps passwords in plain text when told to. Yours doesn't use it; stealers always look.",
		Root:        func(u config.UserInfo) string { return j(u.Profile, ".git-credentials") },
		Files: func(u config.UserInfo) []FileSpec {
			return []FileSpec{{Path: j(u.Profile, ".git-credentials"), Audit: true, Text: true, Gen: genGitCredentials}}
		},
	},
	{
		ID: "aws", Name: "AWS credentials backup (~/.aws)", Category: "Credentials", Kind: KindCanary, Default: true,
		Description: "A backup copy of AWS keys, which no AWS tool reads. With canary tokens on, the keys email you if anyone ever uses them.",
		Files: func(u config.UserInfo) []FileSpec {
			name, alt := varyFile(u, "aws", "credentials.bak", "credentials.old", "credentials.backup", "credentials.orig", "credentials~", "credentials.save")
			return []FileSpec{{Path: j(u.Profile, ".aws", name), Alt: alt, Audit: true, Text: true, Gen: genAWSBackup}}
		},
	},
}
