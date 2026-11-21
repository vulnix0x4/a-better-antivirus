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

	// ---- Browsers you do use: a fake profile inside the real one ----
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
