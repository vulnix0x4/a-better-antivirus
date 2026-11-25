//go:build !windows

package procinfo

// Browser is Windows only for now: elsewhere ABA judges a browser going
// through a fake profile the way it always has.
func Browser(pid uint32, image string) (*BrowserInstance, error) { return nil, ErrUnsupported }
