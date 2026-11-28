package sysenv

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Machine is the machine's locations: the Windows folder from the kernel
// (GetSystemWindowsDirectory), the rest from HKLM (ProfileList, Windows'
// CurrentVersion, the machine environment), which only administrators can
// change. Not SHGetKnownFolderPath: on the app's main thread (which Wails
// locks before main runs) it never returns.
//
// In tests (only), ProgramData, ProgramW6432/ProgramFiles and
// ProgramFiles(x86) from the environment win, so tests can point ABA at a
// folder of their own.
func Machine() Values {
	v := machine()
	if testing.Testing() {
		over := func(p *string, names ...string) {
			for _, n := range names {
				if e := os.Getenv(n); e != "" {
					*p = e
					return
				}
			}
		}
		over(&v.ProgramData, "ProgramData")
		over(&v.ProgramFiles, "ProgramW6432", "ProgramFiles")
		over(&v.ProgramFilesX86, "ProgramFiles(x86)")
	}
	return v
}

var machine = sync.OnceValue(readMachine)

func readMachine() Values {
	var v Values
	if sr, err := windows.GetSystemWindowsDirectory(); err == nil && filepath.IsAbs(sr) {
		v.SystemRoot = sr
	}
	v.SystemDrive = drive(v.Defaults().SystemRoot)
	base := Values{SystemRoot: v.Defaults().SystemRoot, SystemDrive: v.SystemDrive}.vars()
	abs := func(raw string) string {
		x, ok := Expand(raw, base)
		if !ok || !filepath.IsAbs(x) {
			return ""
		}
		return filepath.Clean(x)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileList, registry.QUERY_VALUE); err == nil {
		v.ProgramData = abs(str(k, "ProgramData"))
		v.Public = abs(str(k, "Public"))
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		v.ProgramFiles = abs(str(k, "ProgramFilesDir"))
		v.ProgramFilesX86 = abs(str(k, "ProgramFilesDir (x86)"))
		v.CommonFiles = abs(str(k, "CommonFilesDir"))
		v.CommonFilesX86 = abs(str(k, "CommonFilesDir (x86)"))
		k.Close()
	}
	d := v.Defaults()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE); err == nil {
		vars := d.vars()
		// The machine's other variables may be used in its PATH (rarely).
		if names, err := k.ReadValueNames(-1); err == nil {
			for _, n := range names {
				if _, ok := lookupFold(vars, n); ok {
					continue
				}
				if x, ok := Expand(str(k, n), d.vars()); ok {
					vars[n] = x
				}
			}
		}
		v.Path = ExpandList(str(k, "Path"), vars)
		v.PathExt = str(k, "PATHEXT")
		v.PSModulePath = ExpandList(str(k, "PSModulePath"), vars)
		k.Close()
	}
	return v
}

const profileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

func str(k registry.Key, name string) string {
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return s
}

// ProfileDir is the profile folder of the account sid (C:\Users\name), from
// the machine's list of profiles, or "" if it has none.
func ProfileDir(sid string) string {
	if sid == "" || strings.ContainsAny(sid, `\/`) {
		return ""
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileList+`\`+sid, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	x, ok := Expand(str(k, "ProfileImagePath"), Machine().Defaults().vars())
	if !ok || !filepath.IsAbs(x) {
		return ""
	}
	return filepath.Clean(x)
}

// TokenProfile is the profile folder of tok's account.
func TokenProfile(tok windows.Token) string {
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return ProfileDir(u.User.Sid.String())
}

// CurrentProfile is the profile folder of the account this process runs as.
func CurrentProfile() string { return TokenProfile(windows.GetCurrentProcessToken()) }

// LocalAppData is the account's own Local AppData (the usual place in its
// profile; the person may have moved theirs, but it is theirs either way),
// or "" when its profile isn't known.
func LocalAppData() string {
	p := CurrentProfile()
	if p == "" {
		return ""
	}
	return filepath.Join(p, "AppData", "Local")
}

// Environ is this process's environment, cleaned (see Clean): what to hand
// a program an administrator's process starts.
func Environ() []string { return Clean(os.Environ(), Machine(), CurrentProfile()) }

// CleanProcess replaces this process's own environment with Environ, so
// whatever reads it later (here, or in anything started from here) sees the
// machine's locations.
func CleanProcess() {
	want := map[string]string{}
	for _, kv := range Environ() {
		if name, val, ok := strings.Cut(kv, "="); ok && name != "" {
			want[strings.ToUpper(name)] = name + "=" + val
		}
	}
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if w, ok := want[strings.ToUpper(name)]; !ok {
			os.Unsetenv(name)
		} else if w != kv {
			os.Unsetenv(name) // the replacement may spell the name differently
		}
	}
	for _, kv := range want {
		name, val, _ := strings.Cut(kv, "=")
		if os.Getenv(name) != val {
			os.Setenv(name, val)
		}
	}
}

// CleanProcessIfElevated is CleanProcess for a program started with an
// administrator's full rights by a person (not SYSTEM, whose environment is
// the machine's already, and not a program without those rights, which
// has nothing to protect).
func CleanProcessIfElevated() {
	tok := windows.GetCurrentProcessToken()
	if !tok.IsElevated() {
		return
	}
	if u, err := tok.GetTokenUser(); err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return
	}
	CleanProcess()
}
