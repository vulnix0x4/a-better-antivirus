//go:build !windows

package service

import "github.com/vulnix0x4/a-better-antivirus/internal/alerts"

// openApp: no desktop app here yet (macOS and Linux need a security design
// of their own); the popup it is.
func (s *server) openApp(a *alerts.Alert) bool { return false }
