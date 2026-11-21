package netguard

// Linux isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a Linux backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

var errNotYet = platform.Unsupported("cutting network access")

// Isolate blocks all inbound and outbound connections except loopback and
// selfExe (ABA's service, so phone alerts still get out).
func Isolate(selfExe string) error { return errNotYet }

// Unisolate removes isolation. Since ABA can't isolate a Linux machine yet,
// there is never anything to remove: that's not an error (`aba release` and
// uninstall undo "everything", and on Linux this part is nothing).
func Unisolate() error { return nil }

// BlockProgram blocks all network traffic of one executable.
func BlockProgram(path string) error { return errNotYet }

// UnblockProgram removes a program block (there are none yet: see Unisolate).
func UnblockProgram(path string) error { return nil }

// GetStatus reports what is in place right now.
func GetStatus() (Status, error) { return Status{}, errNotYet }

// RemoveAll removes everything ABA ever put in place (uninstall): nothing,
// so far.
func RemoveAll() error { return nil }

// DisableAdapters is the blunt fallback for isolation: it turns off every
// enabled network adapter and returns their names.
func DisableAdapters() ([]string, error) { return nil, errNotYet }

// EnableAdapters turns the named adapters back on (none were turned off).
func EnableAdapters(names []string) error { return nil }
