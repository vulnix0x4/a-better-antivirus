package sysenv

import (
	"slices"
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	vars := map[string]string{"SystemDrive": "D:", "SystemRoot": `D:\Win`}
	for in, want := range map[string]string{
		`%SystemDrive%\ProgramData`:     `D:\ProgramData`,
		`%systemroot%\system32`:         `D:\Win\system32`,
		`C:\plain`:                      `C:\plain`,
		`50% off`:                       `50% off`,
		`%SystemDrive%%SystemRoot%`:     `D:D:\Win`,
		`%SYSTEMDRIVE%\Users\%USERNAME`: `D:\Users\%USERNAME`,
	} {
		got, ok := Expand(in, vars)
		if !ok || got != want {
			t.Errorf("Expand(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	// A variable it doesn't know is never looked up elsewhere.
	if got, ok := Expand(`%USERPROFILE%\x`, vars); ok {
		t.Errorf("unknown variable expanded to %q", got)
	}
}

func TestExpandList(t *testing.T) {
	vars := map[string]string{"SystemRoot": `C:\Windows`}
	got := ExpandList(`%SystemRoot%\system32;;%NOPE%\bin;C:\Tools;`, vars)
	if got != `C:\Windows\system32;C:\Tools` {
		t.Errorf("got %q", got)
	}
}

func TestDefaults(t *testing.T) {
	d := Values{SystemRoot: `E:\Windows`}.Defaults()
	if d.SystemDrive != "E:" || d.ProgramData != `E:\ProgramData` || d.ProgramFiles != `E:\Program Files` ||
		d.CommonFilesX86 != `E:\Program Files (x86)\Common Files` || !strings.HasPrefix(d.Path, `E:\Windows\system32;`) {
		t.Errorf("defaults: %+v", d)
	}
	if (Values{}).Defaults().SystemRoot != `C:\Windows` {
		t.Error("no Windows folder: C:\\Windows")
	}
}

func get(env []string, name string) (string, int) {
	val, n := "", 0
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, name) {
			val = v
			n++
		}
	}
	return val, n
}

// What a person put in HKCU\Environment never reaches an administrator's
// process for the locations ABA trusts, nor for what loads code.
func TestCleanReplacesPlantedLocations(t *testing.T) {
	m := Values{
		SystemRoot: `C:\Windows`, ProgramData: `C:\ProgramData`, ProgramFiles: `C:\Program Files`,
		ProgramFilesX86: `C:\Program Files (x86)`, Path: `C:\Windows\system32;C:\Windows`,
	}
	planted := []string{
		`=C:=C:\Users\me`,
		`programdata=C:\Users\me\evil`, // any case
		`ALLUSERSPROFILE=C:\Users\me\evil`,
		`ProgramFiles=C:\Users\me\pf`,
		`ProgramW6432=C:\Users\me\pf`,
		`ProgramFiles(x86)=C:\Users\me\pf86`,
		`SystemRoot=C:\Users\me\win`,
		`windir=C:\Users\me\win`,
		`ComSpec=C:\Users\me\cmd.exe`,
		`Path=C:\Users\me\bin;C:\Windows\system32`,
		`PSModulePath=C:\Users\me\mods`,
		`TEMP=C:\Windows\System32`,
		`TMP=C:\Windows\System32`,
		`LOCALAPPDATA=C:\Windows\System32\config`,
		`COR_ENABLE_PROFILING=1`,
		`COR_PROFILER_PATH=C:\Users\me\p.dll`,
		`DOTNET_STARTUP_HOOKS=C:\Users\me\h.dll`,
		`__COMPAT_LAYER=RunAsInvoker`,
		`GODEBUG=winsymlink=0`,
		`USERNAME=me`,
		`HTTPS_PROXY=http://proxy:8080`,
	}
	got := Clean(planted, m, `C:\Users\me`)
	want := map[string]string{
		"ProgramData":       `C:\ProgramData`,
		"ALLUSERSPROFILE":   `C:\ProgramData`,
		"ProgramFiles":      `C:\Program Files`,
		"ProgramW6432":      `C:\Program Files`,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
		"SystemRoot":        `C:\Windows`,
		"windir":            `C:\Windows`,
		"ComSpec":           `C:\Windows\system32\cmd.exe`,
		"Path":              `C:\Windows\system32;C:\Windows`,
		"TEMP":              `C:\Users\me\AppData\Local\Temp`,
		"TMP":               `C:\Users\me\AppData\Local\Temp`,
		"LOCALAPPDATA":      `C:\Users\me\AppData\Local`,
		"USERPROFILE":       `C:\Users\me`,
		"USERNAME":          "me",
		"HTTPS_PROXY":       "http://proxy:8080",
	}
	for name, w := range want {
		if v, n := get(got, name); v != w || n != 1 {
			t.Errorf("%s = %q (%d times), want %q", name, v, n, w)
		}
	}
	for _, name := range []string{"COR_ENABLE_PROFILING", "COR_PROFILER_PATH", "DOTNET_STARTUP_HOOKS", "__COMPAT_LAYER", "GODEBUG"} {
		if _, n := get(got, name); n != 0 {
			t.Errorf("%s kept", name)
		}
	}
	if v, _ := get(got, "PSModulePath"); strings.Contains(v, `\me\`) {
		t.Errorf("PSModulePath = %q", v)
	}
	if !slices.Contains(got, `=C:=C:\Users\me`) {
		t.Error("per-drive folder entry dropped")
	}
}

func TestCleanWithoutProfileKeepsPersonFolders(t *testing.T) {
	got := Clean([]string{`TEMP=C:\Users\me\AppData\Local\Temp`}, Values{}, "")
	if v, _ := get(got, "TEMP"); v != `C:\Users\me\AppData\Local\Temp` {
		t.Errorf("TEMP = %q", v)
	}
	if v, _ := get(got, "ProgramData"); v != `C:\ProgramData` {
		t.Errorf("ProgramData = %q (defaults)", v)
	}
}
