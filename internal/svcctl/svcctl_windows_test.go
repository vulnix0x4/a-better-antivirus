package svcctl

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// rightsOf maps each account in lockedSDDL to the rights it's granted, as
// SDDL's two-letter codes.
func rightsOf(t *testing.T, sddl string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, ace := range strings.Split(strings.Trim(aces(sddl), "()"), ")(") {
		f := strings.Split(ace, ";")
		if len(f) != 6 || f[0] != "A" || len(f[2])%2 != 0 {
			t.Fatalf("unexpected entry %q in %s", ace, sddl)
		}
		r := map[string]bool{}
		for i := 0; i < len(f[2]); i += 2 {
			r[f[2][i:i+2]] = true
		}
		out[f[5]] = r
	}
	return out
}

// Only SYSTEM and administrators may send the service commands, stop it or
// change it. Everyone else may see that it's there and whether it runs: the
// dashboard needs that without admin rights.
func TestOnlyAdminsMaySendTheServiceCommands(t *testing.T) {
	if _, err := windows.SecurityDescriptorFromString(lockedSDDL); err != nil {
		t.Fatalf("lockedSDDL doesn't parse: %v", err)
	}
	who := rightsOf(t, lockedSDDL)
	for _, admin := range []string{"SY", "BA"} {
		for _, need := range []string{"CR", "RP", "WP", "DC", "WD", "LC"} { // custom commands, start, stop, configure, permissions, status
			if !who[admin][need] {
				t.Errorf("%s lost %s", admin, need)
			}
		}
	}
	others := 0
	for acct, rights := range who {
		if acct == "SY" || acct == "BA" {
			continue
		}
		others++
		for _, never := range []string{"CR", "RP", "WP", "DT", "DC", "SD", "WD", "WO"} {
			if rights[never] {
				t.Errorf("%s may %s: only SYSTEM and administrators should", acct, never)
			}
		}
		if !rights["LC"] {
			t.Errorf("%s can't see whether the service runs: `aba status` needs that without admin rights", acct)
		}
	}
	if others == 0 {
		t.Error("nobody but admins can see the service: `aba status` would break without admin rights")
	}
}

// On a real service (needs admin rights): what Windows gives a new service
// lets signed-in users send it custom commands; harden takes that away and
// sets the description, and has nothing to do the second time.
func TestHardenARealService(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("creating a service needs admin rights")
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	exe, _ := os.Executable()
	name := fmt.Sprintf("ABAHardenTest%d", time.Now().UnixNano()%1e9)
	s, err := m.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, DisplayName: name, Description: "before"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer s.Delete()

	before, err := windows.GetNamedSecurityInfo(name, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a new service: %s", before.String())
	if iu := rightsOf(t, before.String())["IU"]; !iu["CR"] {
		t.Logf("note: this Windows doesn't let interactive users send custom commands by default")
	}

	changed, err := harden(name, "after")
	if err != nil || !changed {
		t.Fatalf("harden: changed=%v err=%v", changed, err)
	}
	after, err := windows.GetNamedSecurityInfo(name, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := windows.SecurityDescriptorFromString(lockedSDDL)
	if aces(after.String()) != aces(want.String()) {
		t.Fatalf("permissions after harden: %s, want %s", after.String(), want.String())
	}
	if c, err := s.Config(); err != nil || c.Description != "after" {
		t.Fatalf("description: %q %v", c.Description, err)
	}
	if changed, err := harden(name, "after"); err != nil || changed {
		t.Fatalf("second harden: changed=%v err=%v (nothing should be left to do)", changed, err)
	}
}
