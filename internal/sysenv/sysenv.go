// Package sysenv gives the machine's own folder locations (Windows, Program
// Files, ProgramData), read from settings only administrators can change,
// never from environment variables.
//
// Why: on Windows a person's environment includes HKCU\Environment, which is
// theirs (and so any program running as them) to write, and it goes along
// when they start something as administrator (UAC keeps the same profile),
// and when the service starts the app for them with their elevated token. A
// ProgramData or ProgramFiles planted there would make an elevated ABA read
// its state, alerts and config from a folder the planter owns (fake process
// IDs to kill, say) and write evidence where they can read it. So every
// location ABA trusts comes from here, and the elevated app and CLI replace
// those variables (and drop the few that steer code loading) before anything
// they start inherits them: Clean.
//
// The pure parts (here) are tested on every system; the registry reads are in
// sysenv_windows.go.
package sysenv

import (
	"sort"
	"strings"
)

// Values are the machine's locations. An empty field is unknown.
type Values struct {
	SystemRoot      string // C:\Windows
	SystemDrive     string // C:
	ProgramData     string // C:\ProgramData
	Public          string // C:\Users\Public
	ProgramFiles    string // C:\Program Files (the native one)
	ProgramFilesX86 string // C:\Program Files (x86)
	CommonFiles     string // C:\Program Files\Common Files
	CommonFilesX86  string // C:\Program Files (x86)\Common Files
	Path            string // the machine's PATH, expanded
	PathExt         string
	PSModulePath    string // the machine's, expanded
}

// Defaults fills what's missing from the Windows folder (the one location
// Windows itself reports, from the kernel): the usual layout.
func (v Values) Defaults() Values {
	if v.SystemRoot == "" {
		v.SystemRoot = `C:\Windows`
	}
	if v.SystemDrive == "" {
		v.SystemDrive = drive(v.SystemRoot)
	}
	d := v.SystemDrive
	set := func(p *string, def string) {
		if *p == "" {
			*p = def
		}
	}
	set(&v.ProgramData, d+`\ProgramData`)
	set(&v.Public, d+`\Users\Public`)
	set(&v.ProgramFiles, d+`\Program Files`)
	set(&v.ProgramFilesX86, d+`\Program Files (x86)`)
	set(&v.CommonFiles, v.ProgramFiles+`\Common Files`)
	set(&v.CommonFilesX86, v.ProgramFilesX86+`\Common Files`)
	sr := v.SystemRoot
	set(&v.Path, sr+`\system32;`+sr+`;`+sr+`\System32\Wbem;`+sr+`\System32\WindowsPowerShell\v1.0\`)
	set(&v.PathExt, ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC")
	set(&v.PSModulePath, v.ProgramFiles+`\WindowsPowerShell\Modules;`+sr+`\system32\WindowsPowerShell\v1.0\Modules`)
	return v
}

// drive is the "C:" of `C:\Windows`.
func drive(p string) string {
	if len(p) >= 2 && p[1] == ':' {
		return p[:2]
	}
	return "C:"
}

// Expand replaces %NAME% in s with vars[NAME] (names ignore case, as
// Windows'). It reports false when s names a variable vars doesn't have: the
// caller drops such a value rather than look it up in the environment.
func Expand(s string, vars map[string]string) (string, bool) {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			b.WriteString(s)
			return b.String(), true // a lone %: not a variable
		}
		name := s[i+1 : i+1+j]
		v, ok := lookupFold(vars, name)
		if !ok {
			return "", false
		}
		b.WriteString(s[:i])
		b.WriteString(v)
		s = s[i+2+j:]
	}
}

func lookupFold(vars map[string]string, name string) (string, bool) {
	if v, ok := vars[name]; ok {
		return v, true
	}
	for k, v := range vars {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// ExpandList expands each ';'-separated entry of s, dropping the empty ones
// and those that name a variable vars doesn't have.
func ExpandList(s string, vars map[string]string) string {
	var out []string
	for _, e := range strings.Split(s, ";") {
		if e == "" {
			continue
		}
		if x, ok := Expand(e, vars); ok && x != "" {
			out = append(out, x)
		}
	}
	return strings.Join(out, ";")
}

// vars are the names Values gives, for Expand.
func (v Values) vars() map[string]string {
	return map[string]string{
		"SystemRoot": v.SystemRoot, "windir": v.SystemRoot, "SystemDrive": v.SystemDrive,
		"ProgramData": v.ProgramData, "ALLUSERSPROFILE": v.ProgramData, "PUBLIC": v.Public,
		"ProgramFiles": v.ProgramFiles, "ProgramW6432": v.ProgramFiles, "ProgramFiles(x86)": v.ProgramFilesX86,
		"CommonProgramFiles": v.CommonFiles, "CommonProgramW6432": v.CommonFiles, "CommonProgramFiles(x86)": v.CommonFilesX86,
	}
}

// dropped are variables that make Windows or a runtime load code or change
// how it checks things, which a person's own environment must not do to an
// administrator's process: application compatibility shims, .NET profilers
// (PowerShell is .NET: COR_PROFILER_PATH loads any DLL into it), and Go's
// GODEBUG (it can change how Go treats junctions, among other things).
var droppedPrefixes = []string{"COR_", "CORECLR_", "COMPLUS_", "DOTNET_"}
var droppedNames = []string{"__COMPAT_LAYER", "__PSLockdownPolicy", "GODEBUG", "GOTRACEBACK"}

// Clean is environ ("NAME=value" entries) for an administrator's process:
// every machine location from v (not what environ says), PATH and
// PSModulePath the machine's own (the person's additions name folders they
// can write to), the per-person folders from profile (their profile folder,
// from the machine's list of profiles; skipped when ""), and none of the
// variables that steer code loading. Everything else is kept as it was.
func Clean(environ []string, v Values, profile string) []string {
	v = v.Defaults()
	set := v.vars()
	set["ComSpec"] = v.SystemRoot + `\system32\cmd.exe`
	set["Path"] = v.Path
	set["PATHEXT"] = v.PathExt
	set["PSModulePath"] = v.PSModulePath
	if profile != "" {
		set["USERPROFILE"] = profile
		set["APPDATA"] = profile + `\AppData\Roaming`
		set["LOCALAPPDATA"] = profile + `\AppData\Local`
		set["TEMP"] = profile + `\AppData\Local\Temp`
		set["TMP"] = profile + `\AppData\Local\Temp`
	}
	var out []string
	for _, kv := range environ {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" { // "=C:=C:\x": Windows' per-drive folders
			out = append(out, kv)
			continue
		}
		if dropped(name) {
			continue
		}
		if _, ok := lookupFold(set, name); ok {
			continue // put back below, from v
		}
		out = append(out, kv)
	}
	for _, name := range sortedKeys(set) {
		if val := set[name]; val != "" {
			out = append(out, name+"="+val)
		}
	}
	return out
}

func dropped(name string) bool {
	u := strings.ToUpper(name)
	for _, p := range droppedPrefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	for _, n := range droppedNames {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToLower(keys[i]) < strings.ToLower(keys[j]) })
	return keys
}
