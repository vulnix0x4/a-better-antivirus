package engine

import (
	"path/filepath"
	"testing"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
)

// What a browser's import probe opens: a fake browser's `Local State`, and
// nothing else of it (every system has the fake Vivaldi).
func TestLocalStateProbe(t *testing.T) {
	if _, ok := baits.ByID("vivaldi"); !ok {
		t.Skip("no fake Vivaldi here")
	}
	dir := filepath.Join("home", "bob", "vivaldi", "User Data")
	for path, want := range map[string]bool{
		filepath.Join(dir, "Local State"):           true,
		filepath.Join(dir, "local state"):           true,
		filepath.Join(dir, "Default", "Login Data"): false,
		filepath.Join(dir, "Default", "Cookies"):    false,
	} {
		if got := localStateProbe("vivaldi", path); got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
	if localStateProbe("desktop-passwords", filepath.Join("x", "Local State")) {
		t.Error("only a fake browser's Local State")
	}
	for _, s := range baits.Catalog {
		if s.Inside != nil && localStateProbe(s.ID, filepath.Join("x", "Local State")) {
			t.Errorf("%s: a fake profile inside a real browser has no Local State of its own", s.ID)
		}
	}
}
