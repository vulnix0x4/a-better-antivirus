package cli

import (
	"strings"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/install"
)

// Windows' "Installed apps" list runs a command line that ABA wrote into the
// registry at install time. It has to stay a real aba command: if `uninstall`
// or one of its flags is renamed, the Uninstall button stops working on every
// PC that installed earlier.
func TestInstalledAppsUninstallIsARealCommand(t *testing.T) {
	const exe = `C:\Program Files\File Access Monitor\aba.exe`
	for _, quiet := range []bool{false, true} {
		line := install.UninstallCommand(exe, quiet)
		rest, ok := strings.CutPrefix(line, `"`+exe+`"`)
		if !ok {
			t.Fatalf("%s: the program must come first, in quotes (its folder has spaces)", line)
		}
		c, flags, err := newRoot().Find(strings.Fields(rest))
		if err != nil || c.Name() != "uninstall" {
			t.Fatalf("%s: runs %q, want uninstall (%v)", line, c.Name(), err)
		}
		if err := c.ParseFlags(flags); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if yes, _ := c.Flags().GetBool("yes"); yes != quiet {
			t.Errorf("%s: --yes=%v, want %v (only the quiet form may skip the question)", line, yes, quiet)
		}
	}
}

// The setup program always passes these; they must keep existing.
func TestInstallFlagsTheSetupProgramUses(t *testing.T) {
	c := installCmd()
	args := []string{"--yes", "--keep-settings", "--preset", "balanced", "--learning", "0", "--auto-update=false", "--ntfy-topic", "aba-abc123",
		"--canary-email", "me@example.com", "--baits", "desktop-passwords,discord"}
	if err := c.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	if keep, _ := c.Flags().GetBool("keep-settings"); !keep {
		t.Error("--keep-settings wasn't read")
	}
	if auto, _ := c.Flags().GetBool("auto-update"); auto {
		t.Error("--auto-update=false wasn't read")
	}
}

// The last page of the setup program offers "Run the safe test" and starts
// this. The hidden flag keeps the window open so the result can be read.
func TestSetupProgramsSafeTestIsARealCommand(t *testing.T) {
	c, flags, err := newRoot().Find([]string{"test", "--elevated-pause"})
	if err != nil || c.Name() != "test" {
		t.Fatalf("runs %q, want test (%v)", c.Name(), err)
	}
	if err := c.ParseFlags(flags); err != nil {
		t.Fatal(err)
	}
}
