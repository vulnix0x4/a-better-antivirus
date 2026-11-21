package baits

// macOS isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a macOS backend has to provide.

import (
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// A bait's tripwire is whatever has to be put on the file itself so that
// opening it gets noticed (on Windows, an audit rule). Where the operating
// system watches files without marking them, these have nothing to do.

// SetTripwire puts the tripwire on a bait file.
func SetTripwire(path string) error { return platform.Unsupported("watching a bait file") }

// HasTripwire reports whether the file still has its tripwire.
func HasTripwire(path string) (bool, error) {
	return false, platform.Unsupported("watching a bait file")
}

// ClearTripwire takes the tripwire off again.
func ClearTripwire(path string) error { return platform.Unsupported("watching a bait file") }

// setTimes sets when a file or folder was created, last opened and last
// changed (as far as the file system allows), so a new bait doesn't look new.
func setTimes(path string, created, accessed, written time.Time) {}

// getTimes reads when a file or folder was created and last changed.
func getTimes(path string) (created, written time.Time, ok bool) {
	return created, written, false
}

// ownedBy makes the user with this ID (config.UserInfo.SID) the owner of
// path, when they aren't already: a file planted by an installer running as
// administrator would otherwise stand out among yours.
func ownedBy(path, userID string) {}

// indexedLikeFolder gives a bait the same "index this file" setting as the
// folder it's in, where the operating system has such a setting.
func indexedLikeFolder(path string) {}
