package netguard

// Cutting network access on macOS, without a network extension.
//
// One program: macOS's packet filter (pf) can't tell programs apart, and the
// part of macOS that can (NetworkExtension) needs an entitlement from Apple.
// So BlockProgram closes every connection the program's processes have open
// (pid_shutdown_sockets, root only). The processes are frozen at the same
// time, so they can't open new ones; if you let one run again (`aba resume`),
// it gets its internet back like on Windows.
//
// The whole Mac (Strict mode): pf blocks everything except the Mac talking to
// itself, getting an address on its network (DHCP, IPv6 neighbour
// discovery), and root's own connections to the alert servers (ABA's phone
// alerts), by the addresses the service remembered while it could still look
// them up (DialCache). Measured: everything else blocked, and a phone alert
// still went out. The rules live in an anchor of their own under Apple's
// ("com.apple/*", which macOS's own pf configuration loads), so they sit
// beside Apple's and are removed in one go. pf's rules don't survive a
// restart of the Mac by themselves: the service puts them back each time it
// starts while the Mac is meant to be isolated.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

const anchor = "com.apple/250.FileAccessMonitor"

// tokenFile keeps the reference pf gave ABA when it switched pf on, so that
// ABA releases only its own hold on pf (macOS and other software may hold
// pf on too).
func tokenFile() string { return filepath.Join(paths.DataDir(), "pf-token") }

func pfctl(input string, args ...string) (string, error) {
	cmd := exec.Command("/sbin/pfctl", args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("pfctl %s: %v (%s)", strings.Join(args, " "), err, lastLine(text))
	}
	return text, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// alertAddrs are the addresses ABA's phone alerts go to, as remembered.
func alertAddrs() []string {
	st, err := config.LoadState()
	if err != nil || st == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ips := range st.DialCache {
		for _, ip := range ips {
			if net.ParseIP(ip) != nil && !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
			}
		}
	}
	sort.Strings(out)
	return out
}

// isolationRules is the whole-Mac block.
func isolationRules(allow []string) string {
	var b strings.Builder
	b.WriteString("pass quick on lo0 all\n")
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67 keep state\n")
	b.WriteString("pass in quick inet proto udp from any port 67 to any port 68\n")
	b.WriteString("pass quick inet6 proto ipv6-icmp all\n")
	b.WriteString("pass out quick inet6 proto udp from any port 546 to any port 547 keep state\n")
	if len(allow) > 0 {
		fmt.Fprintf(&b, "pass out quick proto tcp to { %s } user root keep state\n", strings.Join(allow, " "))
	}
	b.WriteString("block drop quick all\n")
	return b.String()
}

var tokenRe = regexp.MustCompile(`Token : (\d+)`)

// Isolate blocks all inbound and outbound connections except loopback and
// root's connections to the alert servers (selfExe isn't used: pf can't go
// by program, and ABA's service is root).
func Isolate(selfExe string) error {
	if _, err := pfctl(isolationRules(alertAddrs()), "-a", anchor, "-f", "-"); err != nil {
		return err
	}
	if b, err := os.ReadFile(tokenFile()); err == nil && strings.TrimSpace(string(b)) != "" {
		if out, _ := pfctl("", "-s", "References"); strings.Contains(out, strings.TrimSpace(string(b))) {
			return nil // ABA's hold on pf is still there
		}
	}
	out, err := pfctl("", "-E")
	if err != nil {
		pfctl("", "-a", anchor, "-F", "all")
		return err
	}
	if m := tokenRe.FindStringSubmatch(out); m != nil {
		os.WriteFile(tokenFile(), []byte(m[1]), 0o600)
	}
	return nil
}

// Unisolate removes isolation.
func Unisolate() error {
	_, err := pfctl("", "-a", anchor, "-F", "all")
	if b, rerr := os.ReadFile(tokenFile()); rerr == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			pfctl("", "-X", t)
		}
		os.Remove(tokenFile())
	}
	if err != nil && strings.Contains(err.Error(), "No such file") {
		return nil
	}
	return err
}

// BlockProgram cuts one program's network access: it closes every
// connection the processes running it have open (see the top of this file).
func BlockProgram(path string) error {
	pids := procinfo.RunningImage(path)
	if len(pids) == 0 {
		return nil
	}
	var errs []string
	for _, pid := range pids {
		if err := procinfo.ShutdownSockets(pid); err != nil {
			errs = append(errs, fmt.Sprintf("pid %d: %v", pid, err))
		}
	}
	if len(errs) == len(pids) {
		return errors.New("couldn't close its connections: " + strings.Join(errs, "; "))
	}
	return nil
}

// UnblockProgram: nothing is kept in place for one program.
func UnblockProgram(path string) error { return nil }

// GetStatus reports what is in place right now.
func GetStatus() (Status, error) {
	out, err := pfctl("", "-a", anchor, "-s", "rules")
	if err != nil {
		return Status{}, err
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "No ALTQ") && !strings.Contains(l, "ALTQ") {
			n++
		}
	}
	return Status{Isolated: n > 0, Rules: n}, nil
}

// RemoveAll removes everything ABA ever put in place (uninstall).
func RemoveAll() error { return Unisolate() }

// services lists the Mac's network services (Wi-Fi, Ethernet…) and whether
// each is switched on.
func services() (map[string]bool, error) {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for i, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 || strings.TrimSpace(l) == "" {
			continue // "An asterisk (*) denotes that a network service is disabled."
		}
		if strings.HasPrefix(l, "*") {
			m[strings.TrimPrefix(l, "*")] = false
		} else {
			m[l] = true
		}
	}
	return m, nil
}

// DisableAdapters is the blunt fallback for isolation: it switches off every
// network service that's on (Wi-Fi, Ethernet…) and returns their names.
func DisableAdapters() ([]string, error) {
	svcs, err := services()
	if err != nil {
		return nil, err
	}
	var off []string
	var errs []string
	for name, on := range svcs {
		if !on {
			continue
		}
		if out, err := exec.Command("/usr/sbin/networksetup", "-setnetworkserviceenabled", name, "off").CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v %s", name, err, strings.TrimSpace(string(out))))
			continue
		}
		off = append(off, name)
	}
	sort.Strings(off)
	if len(errs) > 0 {
		return off, errors.New(strings.Join(errs, "; "))
	}
	return off, nil
}

// EnableAdapters switches the named network services back on.
func EnableAdapters(names []string) error {
	var errs []string
	for _, name := range names {
		if out, err := exec.Command("/usr/sbin/networksetup", "-setnetworkserviceenabled", name, "on").CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v %s", name, err, strings.TrimSpace(string(out))))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
