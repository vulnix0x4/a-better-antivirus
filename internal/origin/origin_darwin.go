package origin

import (
	"strings"

	"golang.org/x/sys/unix"
)

// Of reads what macOS keeps about a download: the quarantine attribute
// ("flags;time;app;id", set by any app that downloads files) says which app
// brought it in, the "where from" attribute (a property list) says from
// where. Programs copied out of a downloaded disk image or archive keep the
// quarantine attribute but usually not the address.
func Of(path string) *Origin {
	o := &Origin{File: path}
	q := xattr(path, "com.apple.quarantine")
	if q != nil {
		if f := strings.Split(string(q), ";"); len(f) >= 3 {
			o.Via = clean(f[2])
		}
	}
	from := bplistStrings(xattr(path, "com.apple.metadata:kMDItemWhereFroms"))
	if len(from) > 0 && useful(clean(from[0])) {
		o.URL = clean(from[0])
	}
	if len(from) > 1 && useful(clean(from[1])) {
		o.Referrer = clean(from[1])
	}
	if q == nil && o.URL == "" && o.Referrer == "" {
		return nil
	}
	return o
}

func xattr(path, name string) []byte {
	b := make([]byte, 8<<10)
	n, err := unix.Getxattr(path, name, b)
	if err != nil || n <= 0 {
		return nil
	}
	return b[:n]
}
