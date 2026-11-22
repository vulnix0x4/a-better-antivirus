// Package platform holds the little that every OS-specific piece of ABA
// shares: the error a piece returns on an operating system it hasn't been
// written for yet.
//
// ABA is split into a core that is the same everywhere (the engine, the
// severity logic, alerts, configuration, the CLI) and a backend per operating
// system. A backend lives in files named *_windows.go, *_linux.go and
// *_darwin.go next to the code that calls it. See "Platforms" in
// CONTRIBUTING.md for what a new one has to provide.
package platform

import (
	"errors"
	"fmt"
	"runtime"
)

// ErrUnsupported is what the parts of ABA that haven't been written for this
// operating system return.
var ErrUnsupported = errors.New("not supported on " + OSName() + " yet")

// Unsupported is ErrUnsupported, saying what was asked for: "freezing a
// process is not supported on Linux yet".
func Unsupported(what string) error { return fmt.Errorf("%s is %w", what, ErrUnsupported) }

// OSName is this operating system's name the way people write it.
func OSName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	}
	return runtime.GOOS
}

// Capital is s with its first letter capitalised, to start a sentence with.
func Capital(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
