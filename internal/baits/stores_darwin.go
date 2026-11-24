package baits

import "github.com/vulnix0x4/a-better-antivirus/internal/config"

// extraStores are real stores no bait stands in for: the keys in your own
// .ssh folder, your AWS keys, the Mac's own password store (the login
// keychain), and Safari's cookies.
func extraStores(u config.UserInfo) []Store {
	return []Store{
		{ID: "ssh", Name: "your SSH keys", Kind: StoreKeys, Root: j(u.Profile, ".ssh"), Files: []string{"id_*", "*.pem"}, Skip: []string{"*.pub"}},
		{ID: "aws-keys", Name: "your AWS keys", Kind: StoreKeys, Root: j(u.Profile, ".aws"), Files: []string{"credentials"}},
		{ID: "keychain", Name: "your login keychain", Kind: StoreKeys, Root: j(u.Profile, "Library", "Keychains"), Files: []string{"login.keychain-db", "login.keychain"}},
		{ID: "safari", Name: "your Safari", Kind: StoreBrowser, Root: j(u.Profile, "Library"),
			Files: []string{"Cookies/Cookies.binarycookies", "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"}},
	}
}
