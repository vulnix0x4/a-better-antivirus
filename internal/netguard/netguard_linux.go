package netguard

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

var errNotYet = platform.Unsupported("cutting network access")

// Isolate blocks all inbound and outbound connections except loopback and
// selfExe (ABA's service, so phone alerts still get out).
func Isolate(selfExe string) error { return errNotYet }

// Unisolate removes isolation.
func Unisolate() error { return errNotYet }

// BlockProgram blocks all network traffic of one executable.
func BlockProgram(path string) error { return errNotYet }

// UnblockProgram removes a program block.
func UnblockProgram(path string) error { return errNotYet }

// GetStatus reports what is in place right now.
func GetStatus() (Status, error) { return Status{}, errNotYet }

// RemoveAll removes everything ABA ever put in place (uninstall).
func RemoveAll() error { return errNotYet }

// DisableAdapters is the blunt fallback for isolation: it turns off every
// enabled network adapter and returns their names.
func DisableAdapters() ([]string, error) { return nil, errNotYet }

// EnableAdapters turns the named adapters back on.
func EnableAdapters(names []string) error { return errNotYet }
