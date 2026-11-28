//go:build !windows

package sysenv

// CleanProcessIfElevated: only Windows hands a person's own environment
// variables to their elevated programs this way (sudo resets them).
func CleanProcessIfElevated() {}
