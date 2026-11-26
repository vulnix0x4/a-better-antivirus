//go:build !windows

package minertrap

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

// The redirect is Windows only for now. Elsewhere the trap is off, and
// setup doesn't offer it.

// Supported reports whether the trap works on this system.
func Supported() bool { return false }

func Apply() (bool, error) { return false, platform.Unsupported("the miner trap") }

// Remove has nothing to remove here.
func Remove() (int, error) { return 0, nil }

func Installed() (int, error) { return 0, nil }

func Expected() int { return 0 }
