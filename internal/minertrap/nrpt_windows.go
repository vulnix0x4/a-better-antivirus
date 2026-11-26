package minertrap

// The redirect on Windows: Name Resolution Policy Table (NRPT) rules. Each
// rule names DNS namespaces and the DNS server Windows must ask about them,
// instead of the network's. The trap's rules send the pool names (and only
// those) to its responder on Addr. That's the mechanism VPNs and
// DirectAccess use for their own names; unlike the hosts file, it's not
// something Defender treats as a sign of malware, and it can't touch any
// other name.
//
// Where: the local rule store, under the DNS Client service's parameters
// (what Add-DnsClientNrptRule writes). Not the Group Policy store: when that
// has any rule, Windows ignores the local store altogether, so a rule ABA
// put there would switch off the split-DNS rules of a VPN or of Tailscale.
// Only when Group Policy rules are already there (a company PC) does ABA
// add its rules there too, or they'd be ignored.

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	nrptLocal  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptPolicy = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

	// The trap's rules are named {ABA0A0A0-4D49-4E45-5254-5241500000NN}
	// ("MINERTRAP" in hex): anything else under those keys isn't ABA's.
	rulePrefix = "{ABA0A0A0-4D49-4E45-5254-524150"

	// Namespaces per rule: Windows takes many, but VPN software that writes
	// NRPT rules keeps each one short, and so does ABA.
	perRule = 50

	ruleComment = "A Better Antivirus: miner trap. Sends the names of crypto-mining pools to ABA's fake pool on this PC. Removed by `aba miners off` and `aba uninstall`."
)

func ruleName(i int) string { return fmt.Sprintf("%s0000%02X}", rulePrefix, i+1) }

func isOurs(key string) bool { return strings.HasPrefix(strings.ToUpper(key), rulePrefix) }

// rules is the namespaces, split into rules.
func rules() [][]string {
	var out [][]string
	ns := Namespaces()
	for len(ns) > 0 {
		n := min(perRule, len(ns))
		out = append(out, ns[:n])
		ns = ns[n:]
	}
	return out
}

// Supported reports whether the trap works on this system.
func Supported() bool { return true }

// Apply puts the redirect in place (or repairs it): it's idempotent, and
// tells Windows only when something changed.
func Apply() (changed bool, err error) {
	rs := rules()
	changed, err = applyAt(registry.LOCAL_MACHINE, nrptLocal, rs, Addr)
	if err != nil {
		return changed, err
	}
	gp := false
	if policyRulesActive(registry.LOCAL_MACHINE, nrptPolicy) {
		c, err := applyAt(registry.LOCAL_MACHINE, nrptPolicy, rs, Addr)
		if err != nil {
			return changed, err
		}
		changed, gp = changed || c, c
	} else if n, _ := removeAt(registry.LOCAL_MACHINE, nrptPolicy); n > 0 {
		changed = true // the policy rules that made ABA's needed there are gone
	}
	if changed {
		refresh(gp)
	}
	return changed, nil
}

// Remove takes the redirect out: the pool names resolve normally again.
func Remove() (removed int, err error) {
	n1, err1 := removeAt(registry.LOCAL_MACHINE, nrptLocal)
	n2, err2 := removeAt(registry.LOCAL_MACHINE, nrptPolicy)
	if n1+n2 > 0 {
		refresh(n2 > 0)
	}
	return n1 + n2, errors.Join(err1, err2)
}

// Installed counts the trap's rules in place (for `aba doctor`).
func Installed() (int, error) {
	n, err := countAt(registry.LOCAL_MACHINE, nrptLocal)
	if err != nil {
		return 0, err
	}
	m, _ := countAt(registry.LOCAL_MACHINE, nrptPolicy)
	return n + m, nil
}

// Expected is how many rules Apply puts in place.
func Expected() int { return len(rules()) }

func applyAt(root registry.Key, base string, rs [][]string, server string) (bool, error) {
	k, _, err := registry.CreateKey(root, base, registry.ALL_ACCESS)
	if err != nil {
		return false, fmt.Errorf("NRPT rules (%s): %w", base, err)
	}
	defer k.Close()
	changed := false
	for i, names := range rs {
		c, err := writeRule(k, ruleName(i), names, server)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}
	// Rules from a longer list of old.
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return changed, err
	}
	keep := map[string]bool{}
	for i := range rs {
		keep[strings.ToUpper(ruleName(i))] = true
	}
	for _, s := range subs {
		if isOurs(s) && !keep[strings.ToUpper(s)] {
			if err := registry.DeleteKey(k, s); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	return changed, nil
}

// writeRule makes rule name hold exactly what it should, and says whether it
// had to change anything.
func writeRule(parent registry.Key, name string, names []string, server string) (bool, error) {
	k, _, err := registry.CreateKey(parent, name, registry.ALL_ACCESS)
	if err != nil {
		return false, err
	}
	defer k.Close()
	changed := false
	str := func(v, want string) error {
		if got, _, err := k.GetStringValue(v); err == nil && got == want {
			return nil
		}
		changed = true
		return k.SetStringValue(v, want)
	}
	dword := func(v string, want uint32) error {
		if got, _, err := k.GetIntegerValue(v); err == nil && got == uint64(want) {
			return nil
		}
		changed = true
		return k.SetDWordValue(v, want)
	}
	if got, _, err := k.GetStringsValue("Name"); err != nil || !slices.Equal(got, names) {
		changed = true
		if err := k.SetStringsValue("Name", names); err != nil {
			return changed, err
		}
	}
	return changed, errors.Join(
		str("GenericDNSServers", server),
		dword("ConfigOptions", 0x8), // use GenericDNSServers for these names
		dword("Version", 2),
		str("IPSECCARestriction", ""),
		str("Comment", ruleComment),
		str("DisplayName", "A Better Antivirus miner trap"),
	)
}

func removeAt(root registry.Key, base string) (int, error) {
	k, err := registry.OpenKey(root, base, registry.ALL_ACCESS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, s := range subs {
		if !isOurs(s) {
			continue
		}
		if err := registry.DeleteKey(k, s); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func countAt(root registry.Key, base string) (int, error) {
	k, err := registry.OpenKey(root, base, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer k.Close()
	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range subs {
		if isOurs(s) {
			n++
		}
	}
	return n, nil
}

// policyRulesActive: Group Policy has NRPT rules of its own here.
func policyRulesActive(root registry.Key, base string) bool {
	k, err := registry.OpenKey(root, base, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		if !isOurs(s) {
			return true
		}
	}
	return false
}

var (
	dnsapi                    = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
	userenv                   = windows.NewLazySystemDLL("userenv.dll")
	procRefreshPolicyEx       = userenv.NewProc("RefreshPolicyEx")
)

// refresh has the DNS Client service read its rules again, and forget the
// answers it has cached: the change applies at once, not when they expire.
func refresh(policy bool) {
	if scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT); err == nil {
		name, _ := windows.UTF16PtrFromString("Dnscache")
		if h, err := windows.OpenService(scm, name, windows.SERVICE_PAUSE_CONTINUE); err == nil {
			var st windows.SERVICE_STATUS
			windows.ControlService(h, windows.SERVICE_CONTROL_PARAMCHANGE, &st)
			windows.CloseServiceHandle(h)
		}
		windows.CloseServiceHandle(scm)
	}
	if policy && procRefreshPolicyEx.Find() == nil {
		procRefreshPolicyEx.Call(1, 1) // the machine's policy, RP_FORCE
	}
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}
