package baits

import "github.com/vulnix0x4/a-better-antivirus/internal/config"

// extraStores are real stores no bait stands in for: the keys in your own
// .ssh folder, your AWS keys, and the desktop's own password stores (GNOME
// Keyring, KWallet).
func extraStores(u config.UserInfo) []Store {
	return []Store{
		{ID: "ssh", Name: "your SSH keys", Kind: StoreKeys, Root: j(u.Profile, ".ssh"), Files: []string{"id_*", "*.pem"}, Skip: []string{"*.pub"}},
		{ID: "aws-keys", Name: "your AWS keys", Kind: StoreKeys, Root: j(u.Profile, ".aws"), Files: []string{"credentials"}},
		{ID: "keyring", Name: "your desktop's password store (GNOME Keyring or KWallet)", Kind: StoreKeys, Root: j(u.Profile, ".local", "share"),
			Files: []string{"keyrings/*.keyring", "kwalletd/*.kwl"}},
	}
}
