package clipbait

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RecordFile is the list of every bait address handed out, with what its key
// is made from, in ABA's data folder (dir): one line each, "time coin index
// address". It holds no keys (those take the seed, which is with ABA's
// encrypted secrets), only what's needed to find one again.
func RecordFile(dir string) string { return filepath.Join(dir, "clipboard-baits.txt") }

// KeysFromSeed is Keys for a hex seed that record their addresses in the
// record file in dir. Nil if the seed isn't usable.
func KeysFromSeed(seedHex, dir string, logf func(string, ...any)) *Keys {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) < 16 {
		return nil
	}
	path := RecordFile(dir)
	return &Keys{Seed: seed, Record: func(c Coin, i uint64, addr string) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			logf("clipboard bait: recording %s: %v", addr, err)
			return
		}
		defer f.Close()
		fmt.Fprintf(f, "%s %s %d %s\n", time.Now().UTC().Format(time.RFC3339), c, i, addr)
	}}
}

// Lookup finds address in the record file in dir.
func Lookup(dir, address string) (c Coin, index uint64, at time.Time, found bool) {
	f, err := os.Open(RecordFile(dir))
	if err != nil {
		return "", 0, time.Time{}, false
	}
	defer f.Close()
	address = strings.TrimSpace(address)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 4 || !strings.EqualFold(fields[3], address) {
			continue
		}
		i, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339, fields[0])
		return Coin(fields[1]), i, t, true
	}
	return "", 0, time.Time{}, false
}
