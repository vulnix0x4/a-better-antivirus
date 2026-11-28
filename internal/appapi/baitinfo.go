package appapi

import (
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
)

// info is how the app shows one bait: a short label, an icon, a category
// and a sentence about it. Kept here rather than taken from the catalog so
// every system (and the tests) labels a bait the same way; the catalog is
// the fallback for a bait this table doesn't know.
type info struct {
	Label, Icon, Category, Blurb string
	rank                         int // most tempting first
}

// Icons the page draws (CONTRACT.md lists them): doc, grid, hashi, vault,
// globe, chrome, firefox, wallet, telegram, discord, server, cloud, key, git.
var baitTable = map[string]info{
	"discord":             {"Discord login", "discord", "Apps", "Fake token, next to the real one", 0},
	"chrome-profile":      {"Chrome passwords", "chrome", "Browsers", "A fake profile inside your Chrome", 1},
	"metamask":            {"MetaMask wallet", "wallet", "Wallets", "The wallet stealers want most, in a fake browser", 2},
	"ssh-backup":          {"SSH keys", "key", "Credentials", "An old key backup in your .ssh folder", 3},
	"ssh-key":             {"SSH keys", "key", "Credentials", "A key in your .ssh folder", 3},
	"telegram":            {"Telegram session", "telegram", "Apps", "A logged-in session, as stealers want it", 4},
	"desktop-passwords":   {"Password list", "doc", "Files", "A password list on your Desktop", 5},
	"edge-profile":        {"Edge profile", "globe", "Browsers", "A fake profile inside your Edge", 6},
	"exodus":              {"Exodus wallet", "wallet", "Wallets", "A fake Exodus wallet", 7},
	"aws":                 {"AWS keys", "cloud", "Credentials", "Cloud keys that tell on whoever uses them", 8},
	"seed-phrase":         {"Recovery phrase", "grid", "Files", "A wallet recovery phrase in Documents", 9},
	"brave":               {"Brave profile", "globe", "Browsers", "Fake saved passwords and cookies", 10},
	"electrum":            {"Electrum wallet", "wallet", "Wallets", "A fake Electrum wallet", 11},
	"backup-codes":        {"2FA backup codes", "hashi", "Files", "Backup codes in Documents", 12},
	"opera":               {"Opera profile", "globe", "Browsers", "Fake saved passwords and cookies", 13},
	"documents-passwords": {"Passwords in Documents", "doc", "Files", "A password list in Documents", 14},
	"home-passwords":      {"Passwords in your folder", "doc", "Files", "A password list in your home folder", 15},
	"keepass":             {"KeePass database", "vault", "Files", "A password database stealers crack offline", 16},
	"atomic":              {"Atomic wallet", "wallet", "Wallets", "A fake Atomic wallet", 17},
	"vivaldi":             {"Vivaldi profile", "globe", "Browsers", "Fake saved passwords and cookies", 18},
	"yandex":              {"Yandex profile", "globe", "Browsers", "Fake saved passwords", 19},
	"firefox":             {"Firefox profile", "firefox", "Browsers", "Fake saved logins", 20},
	"filezilla":           {"FileZilla servers", "server", "Apps", "Fake saved server logins", 21},
	"git-credentials":     {"Git passwords", "git", "Credentials", "Saved git passwords", 22},
	"gcloud":              {"Google Cloud keys", "cloud", "Credentials", "Fake cloud credentials", 23},
}

var categoryOrder = []string{"Files", "Browsers", "Wallets", "Apps", "Credentials", "Custom"}

func categoryRank(c string) int {
	for i, x := range categoryOrder {
		if x == c {
			return i
		}
	}
	return len(categoryOrder)
}

// baitInfo is how bait id (named name in the state) is shown.
func baitInfo(id, name string) info {
	if i, ok := baitTable[id]; ok {
		return i
	}
	if strings.HasPrefix(id, "custom-") {
		label := strings.TrimSuffix(name, " (custom)")
		if label == "" {
			label = "Your bait"
		}
		return info{Label: label, Icon: "doc", Category: "Custom", Blurb: "A file you made a bait", rank: 100}
	}
	if s, ok := baits.ByID(id); ok {
		return info{Label: capitalize(s.Name), Icon: "doc", Category: s.Category, Blurb: s.Description, rank: 90}
	}
	label := name
	if label == "" {
		label = id
	}
	return info{Label: capitalize(label), Icon: "doc", Category: "Files", rank: 95}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
