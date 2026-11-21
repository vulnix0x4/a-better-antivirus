package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// Under and Same decide things like "is this update file really in ABA's own
// folder" and "is this program in Program Files": they must not be fooled by
// a sibling folder with a longer name, and must follow the operating system
// on whether case matters.
func TestUnderAndSame(t *testing.T) {
	sep := string(filepath.Separator)
	root := filepath.Join(sep+"data", "File Access Monitor")
	in := filepath.Join(root, "updates", "aba.bin")

	if !Under(in, root) || !Under(in, root+sep) {
		t.Errorf("%s should be under %s", in, root)
	}
	for _, not := range []string{root, root + " 2", filepath.Join(sep+"data", "other", "aba.bin")} {
		if Under(not, root) {
			t.Errorf("%s is not under %s", not, root)
		}
	}
	if Under(in, "") {
		t.Error("nothing is under an unknown folder")
	}
	if !Same(root, root+sep) || !Same(filepath.Join(root, "updates", ".."), root) {
		t.Error("the same folder written two ways should compare equal")
	}
	if got := Same(in, strings.ToUpper(in)); got != foldCase {
		t.Errorf("Same ignoring case = %v, but this operating system's file names ignore case: %v", got, foldCase)
	}
	if Key(in) != Clean(in) {
		t.Errorf("Key(%q) = %q", in, Key(in))
	}
}
