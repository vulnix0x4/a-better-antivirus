package baits

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/config"

// Catalog lists every bait, in display order. There are none for Linux yet:
// where each app keeps its data and installs to is different there (see
// catalog_windows.go for the shape of an entry).
var Catalog = []Spec{}

// BrowserUserData returns a decoy browser's "User Data" folder.
func BrowserUserData(u config.UserInfo, id string) string { return "" }

// adminOnly reports whether path is somewhere only administrators can write
// to: what's there was installed, not dropped by a program running as you.
func adminOnly(path string) bool { return false }
