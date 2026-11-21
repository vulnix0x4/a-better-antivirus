package session

// macOS isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a macOS backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

var errNotYet = platform.Unsupported("showing something on the desktop of the people logged in")

// LaunchInActiveSessions runs exe with args as each logged-in user (never
// with the service's own rights). It returns the number of sessions it
// launched into.
func LaunchInActiveSessions(exe string, args ...string) (int, error) {
	return LaunchWithInput(exe, nil, args...)
}

// LaunchWithInput is LaunchInActiveSessions with input on the program's
// standard input. That's how the service hands an alert to the popup: the
// alert files themselves are for administrators only, and a command line can
// be read by anything running as the same user.
func LaunchWithInput(exe string, input []byte, args ...string) (int, error) {
	return 0, errNotYet
}
