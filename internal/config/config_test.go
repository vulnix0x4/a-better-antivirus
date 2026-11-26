package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A config from before setup asked about the traps: both stay off, and its
// version says setup hasn't asked yet.
func TestOldConfigLeavesTrapsOff(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"version":4,"preset":"balanced","autoUpdate":true,"baits":[{"id":"aws"}]}`), 0o644)
	c, err := loadConfigFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClipboardBait || c.MinerTrap || c.Version >= TrapsAskedSince || !c.AutoUpdate {
		t.Fatalf("%+v", c)
	}
	if Default().MinerTrap || Default().ClipboardBait || Default().Version < TrapsAskedSince {
		t.Fatal("a new config switches no trap on by itself")
	}
	os.WriteFile(p, []byte(`{"version":5,"clipboardBait":true,"minerTrap":true}`), 0o644)
	if c, _ := loadConfigFrom(p); !c.ClipboardBait || !c.MinerTrap {
		t.Fatalf("%+v", c)
	}
}
