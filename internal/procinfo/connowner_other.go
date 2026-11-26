//go:build !windows

package procinfo

import (
	"net/netip"

	"github.com/vulnix0x4/a-better-antivirus/internal/platform"
)

// ConnOwner is the process that owns the end of a TCP connection at local
// talking to remote. Only the miner trap asks, and it's Windows only for now.
func ConnOwner(local, remote netip.AddrPort) (uint32, error) {
	return 0, platform.Unsupported("finding a connection's program")
}
