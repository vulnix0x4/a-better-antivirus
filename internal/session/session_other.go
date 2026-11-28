//go:build !windows

package session

// LaunchWithInputIn: no sessions to pick from here; everyone signed in gets it.
func LaunchWithInputIn(sessionID uint32, exe string, input []byte, args ...string) error {
	_, err := LaunchWithInput(exe, input, args...)
	return err
}
