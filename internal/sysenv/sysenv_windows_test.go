package sysenv

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// A person's planted variables (what HKCU\Environment adds to everything
// they start, elevated or not) don't move the machine's locations.
func TestMachineIgnoresTheEnvironment(t *testing.T) {
	evil := t.TempDir()
	for _, n := range []string{"ProgramData", "ALLUSERSPROFILE", "ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "SystemRoot", "windir", "SystemDrive", "PUBLIC"} {
		t.Setenv(n, evil)
	}
	v := readMachine().Defaults()
	for name, got := range map[string]string{"SystemRoot": v.SystemRoot, "ProgramData": v.ProgramData, "ProgramFiles": v.ProgramFiles,
		"ProgramFilesX86": v.ProgramFilesX86, "Public": v.Public, "Path": v.Path} {
		if got == "" || strings.Contains(strings.ToLower(got), strings.ToLower(evil)) {
			t.Errorf("%s = %q follows the environment", name, got)
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if pf, _, _ := k.GetStringValue("ProgramFilesDir"); !strings.EqualFold(pf, v.ProgramFiles) {
		t.Errorf("ProgramFiles = %q, HKLM says %q", v.ProgramFiles, pf)
	}
	if _, err := os.Stat(v.ProgramData); err != nil {
		t.Errorf("ProgramData %q: %v", v.ProgramData, err)
	}
	if _, err := os.Stat(v.SystemRoot + `\System32\kernel32.dll`); err != nil {
		t.Errorf("SystemRoot %q: %v", v.SystemRoot, err)
	}
}

func TestCurrentProfile(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	p := CurrentProfile()
	if p == "" {
		t.Fatal("no profile for this account")
	}
	if strings.EqualFold(p, os.Getenv("USERPROFILE")) {
		t.Errorf("profile %q follows the environment", p)
	}
	if _, err := os.Stat(p); err != nil {
		t.Error(err)
	}
	if ProfileDir(`..\x`) != "" || ProfileDir("") != "" {
		t.Error("a made-up SID has a profile")
	}
}
