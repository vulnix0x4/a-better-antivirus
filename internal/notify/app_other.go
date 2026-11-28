//go:build !windows

package notify

import "github.com/vulnix0x4/a-better-antivirus/internal/alerts"

// openAppFor: no desktop app here yet.
func openAppFor(a *alerts.Alert) (bool, error) { return false, nil }
