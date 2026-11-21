package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Each package manager's database, made up in a temp folder.
func TestOwnerLookup(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "var/lib/dpkg/info/coreutils.list"), "/.\n/bin\n/bin/cat\n/usr/bin/catalog-tool\n")
	write(t, filepath.Join(root, "var/lib/dpkg/info/libc6:amd64.list"), "/usr/lib/x86_64-linux-gnu/libc.so.6\n")
	write(t, filepath.Join(root, "var/lib/dpkg/info/coreutils.md5sums"), "abc  bin/dog\n")
	for path, want := range map[string]string{
		"/usr/bin/cat":                        "coreutils", // listed the pre-merge way, as /bin/cat
		"/bin/cat":                            "coreutils",
		"/usr/bin/catalog-tool":               "coreutils",
		"/usr/bin/ca":                         "", // part of a line isn't a match
		"/bin/dog":                            "", // only .list files count
		"/usr/lib/x86_64-linux-gnu/libc.so.6": "libc6",
	} {
		if got := lookupOwner(root, path); got != want {
			t.Errorf("dpkg: owner of %s = %q, want %q", path, got, want)
		}
	}

	root = t.TempDir()
	write(t, filepath.Join(root, "var/lib/pacman/local/coreutils-9.5-1/files"), "%FILES%\nusr/\nusr/bin/\nusr/bin/cat\n\n%BACKUP%\n")
	write(t, filepath.Join(root, "var/lib/pacman/local/python-pip-24.0-2/files"), "%FILES%\nusr/bin/pip\n")
	if got := lookupOwner(root, "/usr/bin/cat"); got != "coreutils" {
		t.Errorf("pacman: owner of /usr/bin/cat = %q", got)
	}
	if got := lookupOwner(root, "/usr/bin/pip"); got != "python-pip" {
		t.Errorf("pacman: owner of /usr/bin/pip = %q", got)
	}
	if got := lookupOwner(root, "/usr/bin/nope"); got != "" {
		t.Errorf("pacman: owner of /usr/bin/nope = %q", got)
	}

	root = t.TempDir()
	write(t, filepath.Join(root, "lib/apk/db/installed"), "C:Q1abc\nP:busybox\nV:1.36\nF:bin\nR:busybox\nF:usr/bin\nR:env\n\nP:curl\nF:usr/bin\nR:curl\n")
	if got := lookupOwner(root, "/usr/bin/curl"); got != "curl" {
		t.Errorf("apk: owner of /usr/bin/curl = %q", got)
	}
	if got := lookupOwner(root, "/bin/busybox"); got != "busybox" {
		t.Errorf("apk: owner of /bin/busybox = %q", got)
	}
}

// The index gives the same answers as searching the lists.
func TestOwnerIndex(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "var/lib/dpkg/info/coreutils.list"), "/.\n/bin\n/bin/cat\n/usr/share/doc/coreutils/README\n")
	write(t, filepath.Join(root, "var/lib/dpkg/info/libc6:amd64.list"), "/usr/lib/x86_64-linux-gnu/libc.so.6")
	write(t, filepath.Join(root, "var/lib/pacman/local/python-pip-24.0-2/files"), "%FILES%\nusr/bin/\nusr/bin/pip\n\n%BACKUP%\netc/pip.conf\n")
	write(t, filepath.Join(root, "lib/apk/db/installed"), "P:curl\nF:usr/bin\nR:curl\n")
	ix := buildIndex(root)
	for path, want := range map[string]string{
		"/usr/bin/cat": "coreutils", "/bin/cat": "coreutils", "/usr/lib/x86_64-linux-gnu/libc.so.6": "libc6",
		"/usr/bin/pip": "python-pip", "/usr/bin/curl": "curl", "/usr/bin/nope": "", "/etc/pip.conf": "", "/usr/bin": "",
	} {
		if got, _ := ix.find(path); got != want {
			t.Errorf("index: owner of %s = %q, want %q", path, got, want)
		}
	}
	if !unindexed("/usr/share/doc/coreutils/README") {
		t.Error("documentation is left out of the index")
	}
	if _, ok := ix.find("/usr/share/doc/coreutils/README"); ok {
		t.Error("…so it shouldn't be in it")
	}
	if ix.rpm {
		t.Error("no rpm database here")
	}
}

// A file in a folder that isn't root's is never vouched for, whatever it is.
func TestUserFoldersAreNotRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, a temp folder is root's")
	}
	p := filepath.Join(t.TempDir(), "tool")
	write(t, p, "#!/bin/sh\n")
	if ok, why := RootOnly(p); ok || why == "" {
		t.Fatalf("RootOnly(%s) = %v, %q", p, ok, why)
	}
	if r := Verify(p); r.Valid || r.Signed {
		t.Fatalf("Verify(%s) = %+v", p, r)
	}
	if ok, _ := RootOnly("/tmp/x"); ok {
		t.Fatal("/tmp is everyone's")
	}
	if ok, why := RootOnly("/nix/store/abc-tool/bin/tool"); ok || !strings.Contains(why, "/nix/store") {
		t.Fatalf("the Nix store isn't root-only: %v %q", ok, why)
	}
}

// The system's own shell: root-only, and (on a system with a package manager
// ABA knows) owned by a package.
func TestSystemShell(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if ok, why := RootOnly(sh); !ok {
		t.Fatalf("%s should be root-only: %s", sh, why)
	}
	r := Verify("/bin/sh")
	if _, err := os.Stat("/var/lib/dpkg/info"); err == nil {
		if !r.Valid || r.Signer == "" {
			t.Fatalf("Verify(/bin/sh) on a dpkg system = %+v", r)
		}
	}
	t.Logf("/bin/sh -> %s: %+v", sh, r)
}

func TestSandboxed(t *testing.T) {
	for path, want := range map[string]string{
		"/snap/firefox/4793/usr/lib/firefox/firefox":                       "firefox (snap)",
		"/snap/bin/firefox":                                                "",
		"/var/lib/flatpak/app/org.gimp.GIMP/x86_64/stable/abc/files/bin/x": "org.gimp.GIMP (flatpak)",
		"/usr/bin/cat": "",
	} {
		if got := sandboxed(path); got != want {
			t.Errorf("sandboxed(%s) = %q, want %q", path, got, want)
		}
	}
}
