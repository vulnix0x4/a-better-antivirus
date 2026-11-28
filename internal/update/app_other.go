//go:build !windows

package update

import "errors"

// No desktop app here yet.

func installedApp() string { return "" }
func appIsWanted() bool    { return false }
func installAppFile(src string) error {
	return errors.New("there is no desktop app on this system")
}
