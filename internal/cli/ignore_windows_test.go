package cli

import "testing"

// A rule that allows evasion-like reads has to name a program nothing else
// can pass for: a publisher, or a folder only administrators can write to.
func TestAllowTricksNeedsAPinnedProgram(t *testing.T) {
	for _, c := range []struct {
		pattern, signer string
		tricks, ok      bool
	}{
		{`C:\Users\bob\AppData\Local\Programs\SyncTool\sync.exe`, "", true, false},
		{`**\sync.exe`, "", true, false},
		{`C:\Users\bob\AppData\Local\Programs\SyncTool\sync.exe`, "Sync Tool", true, true},
		{`C:\Program Files\Backup\agent.exe`, "", true, true},
		{`C:\Users\bob\tools\mytool.exe`, "", false, true}, // an ordinary rule: as before
	} {
		if why := tricksRuleProblem(c.pattern, c.signer, c.tricks); (why == "") != c.ok {
			t.Errorf("%s signer=%q tricks=%v: %q", c.pattern, c.signer, c.tricks, why)
		}
	}
}
