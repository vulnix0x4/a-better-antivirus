package netrec

import (
	"net/netip"
	"strings"
)

// DNSAddrs picks the addresses out of Windows' DNS client's list of answers
// ("type:  5 example.net;::ffff:93.184.216.34;").
func DNSAddrs(s string) []netip.Addr {
	var out []netip.Addr
	for _, f := range strings.Split(s, ";") {
		f = strings.TrimSpace(f)
		if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}
