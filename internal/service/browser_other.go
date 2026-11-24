//go:build !windows

package service

// VisibleWindow: the browser host policy is Windows only for now (see
// engine's host.go), so this is never needed elsewhere.
func (s *server) VisibleWindow(pids []uint32) (visible, known bool) { return false, false }
