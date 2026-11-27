// Package minertrap is the miner trap: a tripwire for hidden crypto miners.
//
// A hidden miner has to reach a mining pool to be paid, and nearly all of
// them reach one of a few dozen public pools, by name. With the trap on,
// those names (and only those) lead to a fake pool on this PC:
//
//   - On Windows, a Name Resolution Policy Table rule (nrpt_windows.go) sends
//     lookups of the pool names to a small DNS responder (dns.go) that ABA's
//     service runs on Addr, a loopback address nothing else uses. It answers
//     with Addr itself, and only for the names in Pools. The names are data,
//     not code: the list ABA installs next to itself (PoolsFileName).
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
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// Addr is the loopback address the trap's DNS responder and fake pool listen
// on. Not 127.0.0.1, where other software runs DNS proxies of its own; the
// last three numbers spell "aba".
const Addr = "127.97.98.97"

// AddrIP is Addr, parsed.
var AddrIP = netip.MustParseAddr(Addr)

// PoolsFileName is the list of pools whose names lead to the trap: each name,
// and every name under it. It's plain data, one name per line, installed
// next to aba.exe (PoolsFile) and published with every release, in the signed
// checksum list. The copy in this folder, miner-pools.txt, is the one place
// to change it.
//
// It isn't compiled into the program on purpose, and must never be, nor
// embedded in it: the pools' names inside an exe are what antivirus engines
// look for in a crypto miner, and they took ABA for one (v0.10.0).
const PoolsFileName = "miner-pools.txt"

// PoolsFile is the installed list: in ABA's program folder, which only
// administrators can change.
func PoolsFile() string { return filepath.Join(paths.InstallDir(), PoolsFileName) }

// MaxPools is the most names a list may hold: a few dozen are in use.
const MaxPools = 1000

var current struct {
	sync.RWMutex
	pools []string
}

// Pools is the list in use: what SetPools (or LoadPools) last put there.
func Pools() []string {
	current.RLock()
	defer current.RUnlock()
	return slices.Clone(current.pools)
}

// SetPools puts list in use, as it is (ParsePools checks one).
func SetPools(list []string) {
	current.Lock()
	current.pools = slices.Clone(list)
	current.Unlock()
}

// LoadPools reads the installed list and puts it in use. A missing or
// damaged file is an error, and leaves the list in use as it was.
func LoadPools() ([]string, error) {
	b, err := os.ReadFile(PoolsFile())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("the list of mining pools (%s) is missing: %w", PoolsFile(), fs.ErrNotExist)
	case err != nil:
		return nil, fmt.Errorf("the list of mining pools (%s) can't be read: %w", PoolsFile(), err)
	}
	list, err := ParsePools(b)
	if err != nil {
		return nil, fmt.Errorf("the list of mining pools (%s) is damaged: %w", PoolsFile(), err)
	}
	SetPools(list)
	return list, nil
}

// ParsePools reads a list of pools: one name per line, "#" to the end of a
// line is a comment. Every name must be a full DNS name of two labels or
// more (so no list can ever redirect a whole top-level domain, or every
// name), listed once.
func ParsePools(b []byte) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		if c := strings.IndexByte(line, '#'); c >= 0 {
			line = line[:c]
		}
		name := strings.ToLower(strings.TrimSpace(line))
		if name == "" {
			continue
		}
		if !validPool(name) {
			return nil, fmt.Errorf("line %d: %q isn't a mining pool's name", i+1, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("line %d: %s is listed twice", i+1, name)
		}
		seen[name] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, errors.New("it lists no pools")
	}
	if len(out) > MaxPools {
		return nil, fmt.Errorf("it lists %d pools; at most %d make sense", len(out), MaxPools)
	}
	return out, nil
}

// validPool: a DNS name of two labels or more, letters, digits and hyphens.
func validPool(name string) bool {
	labels := strings.Split(name, ".")
	if len(name) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	// The last label is a top-level domain: never only digits (no addresses).
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// Ports are the ports the fake pool listens on: the ones pools give in their
// connection guides, with and without TLS (the same port takes either).
var Ports = []int{
	80, 443, 1111, 2222, 3333, 3334, 4444, 5555, 6666, 7777, 8080, 8443, 8888, 9000, 9999,
	10001, 10128, 10343, 12222, 13333, 14433, 14444, 15555, 17777, 19999, 20128, 20535, 33333, 45560, 45700,
}

// TestPool is the pool name `aba miners test` looks up and logs in to: a
// real pool's (pool.<the list's first name>), so the test proves the
// redirect works for real names. The test connects only once the name has
// led to Addr, never anywhere else.
func TestPool() string {
	if p := Pools(); len(p) > 0 {
		return "pool." + p[0]
	}
	return ""
}

// TestPort is the port the test logs in on.
const TestPort = 3333

// Match reports whether name (a DNS name, any case, with or without the
// final dot) is one of the pools or a name under one, and which.
func Match(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" {
		return "", false
	}
	for _, p := range Pools() {
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
	for _, p := range Pools() {
		out = append(out, p, "."+p)
	}
	return out
}
