package session

import "testing"

func TestPickToken(t *testing.T) {
	cases := []struct {
		name  string
		typ   uint32
		admin bool
		want  TokenPick
	}{
		{"admin, UAC on", elevationLimited, false, PickLinked},
		{"already elevated", elevationFull, true, PickOwnFull},
		{"UAC off admin", elevationDefault, true, PickOwnFull},
		{"standard user", elevationDefault, false, PickOwnLocked},
		{"unknown type, not admin", 0, false, PickOwnLocked},
	}
	for _, c := range cases {
		if got := pickToken(c.typ, c.admin); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if PickOwnLocked.Elevated() || !PickLinked.Elevated() || !PickOwnFull.Elevated() {
		t.Error("Elevated wrong")
	}
}

func TestAdminEnabled(t *testing.T) {
	const users = "S-1-5-32-545"
	if adminEnabled([]tokenGroup{{users, seGroupEnabled}}) {
		t.Error("users only: admin")
	}
	// A filtered (UAC) token: Administrators for deny only.
	if adminEnabled([]tokenGroup{{users, seGroupEnabled}, {sidBuiltinAdministrators, seGroupUseForDenyOnly}}) {
		t.Error("deny-only admin counted")
	}
	if adminEnabled([]tokenGroup{{sidBuiltinAdministrators, 0}}) {
		t.Error("disabled admin counted")
	}
	if !adminEnabled([]tokenGroup{{users, seGroupEnabled}, {sidBuiltinAdministrators, seGroupEnabled | 0x3}}) {
		t.Error("enabled admin not counted")
	}
}
