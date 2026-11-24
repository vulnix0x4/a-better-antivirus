package baits

import "github.com/vulnix0x4/a-better-antivirus/internal/config"

// extraStores are real stores no bait stands in for: the keys in your own
// .ssh folder, and Windows' Credential Manager (saved Windows, network and
// app passwords).
func extraStores(u config.UserInfo) []Store {
	return []Store{
		{ID: "ssh", Name: "your SSH keys", Kind: StoreKeys, Root: j(u.Profile, ".ssh"), Files: []string{"id_*", "*.pem"}, Skip: []string{"*.pub"}},
		{ID: "credman", Name: "your Windows Credential Manager", Kind: StoreKeys, Root: j(u.RoamingAppData, "Microsoft", "Credentials"), Files: []string{"*"}},
		{ID: "credman-local", Name: "your Windows Credential Manager", Kind: StoreKeys, Root: j(u.LocalAppData, "Microsoft", "Credentials"), Files: []string{"*"}},
	}
}
