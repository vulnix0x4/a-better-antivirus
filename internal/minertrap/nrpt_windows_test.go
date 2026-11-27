package minertrap

import (
	"fmt"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// The rules are written to a throwaway key under HKEY_CURRENT_USER, never to
// the real NRPT store: no administrator rights needed, nothing to clean up.
func testBase(t *testing.T) string {
	base := fmt.Sprintf(`Software\ABA-test-nrpt-%d`, os.Getpid())
	t.Cleanup(func() { deleteTree(registry.CURRENT_USER, base) })
	return base + `\DnsPolicyConfig`
}

func deleteTree(root registry.Key, path string) {
	if k, err := registry.OpenKey(root, path, registry.ALL_ACCESS); err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		for _, s := range subs {
			deleteTree(k, s)
		}
		k.Close()
	}
	registry.DeleteKey(root, path)
}

func TestNRPTApplyRemove(t *testing.T) {
	base := testBase(t)
	// Someone else's rule (a VPN's) is there first, and must survive everything.
	other, _, err := registry.CreateKey(registry.CURRENT_USER, base+`\{11111111-2222-3333-4444-555555555555}`, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	other.SetStringsValue("Name", []string{".corp.example"})
	other.Close()

	rs := rules()
	changed, err := applyAt(registry.CURRENT_USER, base, rs, Addr)
	if err != nil || !changed {
		t.Fatalf("first apply: %v %v", changed, err)
	}
	if n, _ := countAt(registry.CURRENT_USER, base); n != len(rs) || n != Expected() {
		t.Fatalf("%d rules, want %d", n, len(rs))
	}
	// Everything is in each rule, as Windows wants it.
	var all []string
	for i := range rs {
		k, err := registry.OpenKey(registry.CURRENT_USER, base+`\`+ruleName(i), registry.QUERY_VALUE)
		if err != nil {
			t.Fatal(err)
		}
		names, _, _ := k.GetStringsValue("Name")
		srv, _, _ := k.GetStringValue("GenericDNSServers")
		opts, _, _ := k.GetIntegerValue("ConfigOptions")
		k.Close()
		if srv != Addr || opts != 8 || len(names) == 0 || len(names) > perRule {
			t.Errorf("rule %d: %q %d %d names", i, srv, opts, len(names))
		}
		all = append(all, names...)
	}
	if !slices.Equal(all, Namespaces()) {
		t.Errorf("namespaces differ: %v", all)
	}
	// The names read back are the list, in its order.
	if got := installedAt(registry.CURRENT_USER, base); !slices.Equal(got, Pools()) {
		t.Errorf("installed pools read back as %q", got)
	}
	// Idempotent: nothing to change the second time.
	if changed, err := applyAt(registry.CURRENT_USER, base, rs, Addr); err != nil || changed {
		t.Errorf("second apply: %v %v", changed, err)
	}
	// Repairs a changed rule, and drops one left from a longer list.
	k, _ := registry.OpenKey(registry.CURRENT_USER, base+`\`+ruleName(0), registry.SET_VALUE)
	k.SetStringValue("GenericDNSServers", "8.8.8.8")
	k.Close()
	extra, _, _ := registry.CreateKey(registry.CURRENT_USER, base+`\`+ruleName(len(rs)+3), registry.ALL_ACCESS)
	extra.Close()
	if changed, err := applyAt(registry.CURRENT_USER, base, rs, Addr); err != nil || !changed {
		t.Errorf("repair: %v %v", changed, err)
	}
	if n, _ := countAt(registry.CURRENT_USER, base); n != len(rs) {
		t.Errorf("%d rules after repair", n)
	}
	if !policyRulesActive(registry.CURRENT_USER, base) {
		t.Error("the other rule wasn't seen")
	}
	// Removing takes all of ABA's and nothing else, twice over.
	if n, err := removeAt(registry.CURRENT_USER, base); err != nil || n != len(rs) {
		t.Errorf("remove: %d %v", n, err)
	}
	if n, err := removeAt(registry.CURRENT_USER, base); err != nil || n != 0 {
		t.Errorf("second remove: %d %v", n, err)
	}
	if n, _ := countAt(registry.CURRENT_USER, base); n != 0 {
		t.Errorf("%d left", n)
	}
	k, err = registry.OpenKey(registry.CURRENT_USER, base+`\{11111111-2222-3333-4444-555555555555}`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal("the other rule was removed")
	}
	k.Close()
	// Nothing there at all: fine.
	if n, err := removeAt(registry.CURRENT_USER, base+`\nope`); err != nil || n != 0 {
		t.Errorf("missing key: %d %v", n, err)
	}
}

func TestRuleNames(t *testing.T) {
	for i := 0; i < 20; i++ {
		n := ruleName(i)
		if len(n) != 38 || !isOurs(n) {
			t.Errorf("%q isn't a GUID-shaped name of ours", n)
		}
	}
	if isOurs("{11111111-2222-3333-4444-555555555555}") {
		t.Error("someone else's rule taken for ABA's")
	}
}
