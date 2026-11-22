package origin

import (
	"io"
	"os"
	"strconv"
	"strings"
)

// Of reads path's Mark of the Web: the Zone.Identifier stream browsers,
// mail and chat apps attach to what they download, which Explorer copies onto
// files unpacked from a marked archive. Only the internet zones count (3
// Internet, 4 Restricted): files from this PC or the local network are not
// "downloaded".
func Of(path string) *Origin {
	f, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 8<<10))
	return parseZone(path, string(b))
}

func parseZone(path, s string) *Origin {
	zone := -1
	o := &Origin{File: path}
	for _, line := range strings.Split(strings.TrimPrefix(s, string(rune(0xfeff))), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "zoneid":
			zone, _ = strconv.Atoi(strings.TrimSpace(v))
		case "hosturl":
			if v = clean(v); useful(v) {
				o.URL = v
			}
		case "referrerurl":
			if v = clean(v); useful(v) {
				o.Referrer = v
			}
		}
	}
	if zone < 3 {
		return nil
	}
	return o
}
