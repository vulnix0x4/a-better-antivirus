package procinfo

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Connections lists the sockets the given processes have open: the socket
// inodes behind their file descriptors, looked up in the kernel's tables.
func Connections(pids []uint32) ([]Conn, error) {
	var out []Conn
	for _, pid := range pids {
		inodes := map[string]bool{}
		dir := fmt.Sprintf("/proc/%d/fd", pid)
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if l, err := os.Readlink(dir + "/" + e.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
			}
		}
		if len(inodes) == 0 {
			continue
		}
		// The process's own view of the network (it may be in a namespace).
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
			for i, line := range readLines(fmt.Sprintf("/proc/%d/net/%s", pid, proto)) {
				f := strings.Fields(line)
				if i == 0 || len(f) < 10 || !inodes[f[9]] {
					continue
				}
				c := Conn{PID: pid, Proto: proto, Local: sockAddr(f[1])}
				if r := sockAddr(f[2]); !strings.HasSuffix(r, ":0") {
					c.Remote = r
				}
				if strings.HasPrefix(proto, "tcp") {
					c.State = tcpState(f[3])
				}
				out = append(out, c)
				if len(out) >= 200 {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

// sockAddr turns the kernel's "0100007F:0035" into 127.0.0.1:53.
func sockAddr(s string) string {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s
	}
	raw, err := hex.DecodeString(s[:i])
	port, err2 := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil || err2 != nil || len(raw)%4 != 0 {
		return s
	}
	// Each 32-bit word is written in the machine's byte order.
	for w := 0; w+4 <= len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	return net.JoinHostPort(net.IP(raw).String(), strconv.Itoa(int(port)))
}

func tcpState(h string) string {
	switch strings.ToUpper(h) {
	case "01":
		return "established"
	case "02", "03":
		return "connecting"
	case "0A":
		return "listening"
	case "04", "05", "06", "07", "08", "09", "0B":
		return "closing"
	}
	return ""
}
