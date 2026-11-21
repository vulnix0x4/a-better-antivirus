package cli

// macOS isn't supported yet: this file only lets the rest of ABA build there.
// Everything in it is what a macOS backend has to provide.

import "github.com/vulnix0x4/a-better-antivirus/internal/platform"

// requireAdmin returns nil if this process has administrator rights.
// Otherwise it gets them the way the operating system offers (on Windows:
// relaunches the same command through a prompt, waits for it, and returns
// errRelaunched) or says how to.
func requireAdmin() error {
	return platform.Unsupported("ABA")
}

// shouldPause reports whether to wait for Enter before exiting, because the
// window this runs in would otherwise vanish with the result.
func shouldPause() bool { return false }

// testReader is the running fake stealer of `aba test`.
type testReader struct {
	Path string
	PID  uint32
	As   string // how it was started
}

// startTestReader writes a copy of this program (self) where stealers run
// from and starts it as `test-reader <target>`, without administrator rights:
// the way a real stealer runs.
func startTestReader(self []byte, target string) (*testReader, error) {
	return nil, platform.Unsupported("the safe test")
}

// Close ends the fake stealer (if it's still there) and deletes its file.
func (r *testReader) Close() {}
