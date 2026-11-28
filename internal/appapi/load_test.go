package appapi

import (
	"go/build"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/update"
)

func TestVersionChecksMatchUpdate(t *testing.T) {
	vs := []string{"v0.10.2", "v0.10.10", "v1.0.0", "0.9.0", "dev", "", "v1.2", "v1.2.3-rc1", "v01.2.3", "v1.2.3.4", " v2.0.0 "}
	for _, a := range vs {
		if Updatable(a) != update.Updatable(a) {
			t.Errorf("Updatable(%q) differs", a)
		}
		for _, b := range vs {
			if Newer(a, b) != update.Newer(a, b) {
				t.Errorf("Newer(%q, %q) differs", a, b)
			}
		}
	}
}

// The app must not carry the code that freezes, kills, cuts off or
// updates (that's the CLI's; it also looks like malware to antivirus).
func TestNoActingPackages(t *testing.T) {
	ctx := build.Default
	ctx.GOOS = "windows"
	seen := map[string]bool{}
	var walk func(string)
	walk = func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		pkg, err := ctx.Import(p, ".", 0)
		if err != nil {
			return
		}
		for _, i := range pkg.Imports {
			walk(i)
		}
	}
	walk("github.com/vulnix0x4/a-better-antivirus/internal/appapi")
	for _, bad := range []string{"netguard", "respond", "install", "update", "minertrap", "engine", "service", "clipbait", "machmem", "github.com/tailscale/wf"} {
		p := bad
		if bad[0] != 'g' {
			p = "github.com/vulnix0x4/a-better-antivirus/internal/" + bad
		}
		if seen[p] {
			t.Errorf("appapi imports %s", p)
		}
	}
}
