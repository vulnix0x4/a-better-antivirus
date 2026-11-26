// Package minertrap is the miner trap: a tripwire for hidden crypto miners.
//
// A hidden miner has to reach a mining pool to be paid, and nearly all of
// them reach one of a few dozen public pools, by name. With the trap on,
// those names (and only those) lead to a fake pool on this PC:
//
//   - On Windows, a Name Resolution Policy Table rule (nrpt_windows.go) sends
//     lookups of the pool names to a small DNS responder (dns.go) that ABA's
//     service runs on Addr, a loopback address nothing else uses. It answers
//     with Addr itself, and only for the names in Pools.
//   - The fake pool (server.go) listens on Addr, on the ports pools use, with
//     and without TLS. A program that connects and logs in to mine (the
//     Stratum protocol, stratum.go) has given itself away: the service finds
//     which program owns the other end of the connection and the engine
//     freezes it like a stealer caught at a bait.
//
// Nothing is ever sent off the PC: the fake pool is the only one reached.
// Everything here is the same on every system except the name redirect.
package minertrap

import (
	"net/netip"
	"strings"
)

// Addr is the loopback address the trap's DNS responder and fake pool listen
// on. Not 127.0.0.1, where other software runs DNS proxies of its own; the
// last three numbers spell "aba".
const Addr = "127.97.98.97"

// AddrIP is Addr, parsed.
var AddrIP = netip.MustParseAddr(Addr)

// Pools are the mining pools whose names lead to the trap: each name, and
// every name under it. This list is the one place to change. It holds the
// public pools hidden miners are configured with (most of them mine Monero,
// whose RandomX algorithm runs well on ordinary processors), from public
// analyses of miner malware and the pools' own connection guides.
//
// The pools' websites don't open while the trap is on, so a name is listed
// only where the whole domain is a pool's; where a big company's domain has
// a mining part, only that part is (xmr.f2pool.com, auto.nicehash.com).
var Pools = []string{
	// Monero (RandomX) pools.
	"hashvault.pro", // pool.hashvault.pro: SilentCryptoMiner's default
	"hashvault.sh",  // its backup name
	"supportxmr.com",
	"moneroocean.stream",
	"nanopool.org",
	"c3pool.com",
	"c3pool.org",
	"2miners.com",
	"herominers.com",
	"unmineable.com",
	"xmrpool.eu",
	"xmrpool.net",
	"monerohash.com",
	"minexmr.com", // closed in 2022; old miners still ask for it
	"xmr.f2pool.com",
	"xmr.kryptex.network",
	"xmr-eu.kryptex.network",
	"xmr-us.kryptex.network",
	"xmr-sg.kryptex.network",
	"minergate.com",
	"solopool.org",
	"rplant.xyz",
	"crypto-pool.fr",
	"dwarfpool.com",
	"skypool.org",
	"xmrfast.com",
	"moneropool.com",
	// Pools for other coins that miners hide on processors and graphics cards.
	"ethermine.org",
	"woolypooly.com",
	"k1pool.com",
	"miningpoolhub.com",
	"mine.zpool.ca",
	"auto.nicehash.com",
	// XMRig's own donation pool (on by default in XMRig, so a miner that
	// leaves it on asks for it now and then).
	"donate.v2.xmrig.com",
	"donate.ssl.xmrig.com",
}

// Ports are the ports the fake pool listens on: the ones pools give in their
// connection guides, with and without TLS (the same port takes either).
var Ports = []int{
	80, 443, 1111, 2222, 3333, 3334, 4444, 5555, 6666, 7777, 8080, 8443, 8888, 9000, 9999,
	10001, 10128, 10343, 12222, 13333, 14433, 14444, 15555, 17777, 19999, 20128, 20535, 33333, 45560, 45700,
}

// TestPool is the pool name `aba miners test` looks up and logs in to: a
// real pool's, so the test proves the redirect works for real names. The
// test connects only once the name has led to Addr, never anywhere else.
const TestPool = "pool.supportxmr.com"

// TestPort is the port the test logs in on.
const TestPort = 3333

// Match reports whether name (a DNS name, any case, with or without the
// final dot) is one of the pools or a name under one, and which.
func Match(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" {
		return "", false
	}
	for _, p := range Pools {
		if n == p || strings.HasSuffix(n, "."+p) {
			return p, true
		}
	}
	return "", false
}

// Namespaces are the names the redirect covers, in the form Windows' Name
// Resolution Policy Table takes: each pool's name itself, and ".name" for
// every name under it.
func Namespaces() []string {
	var out []string
	for _, p := range Pools {
		out = append(out, p, "."+p)
	}
	return out
}
