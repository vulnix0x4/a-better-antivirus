// Package appsec holds the security checks the desktop app (cmd/aba-app)
// makes before it lets a browser engine run with administrator rights.
//
// The app runs elevated so that what it shows can't be read or clicked by
// programs running as the person (Windows keeps lower programs away from a
// higher one's windows and memory). The flip side: its WebView2 engine is
// then an administrator's browser, so anything a program running as the
// person can use to steer it is a way to become administrator. Those are:
//
//   - WEBVIEW2_* environment variables (HKCU\Environment is the person's to
//     write), which pick the engine's folder, its profile and its command
//     line (a debugging port, say): ScrubWebView2Env drops them all.
//   - Where the engine is loaded from: only the machine-wide Evergreen
//     runtime under Program Files, in admin-owned folders nobody else may
//     write to (ValidateRuntimeDir, and the ACL checks in the _windows file).
//   - The engine's profile folder: in ABA's admin-only data folder, never in
//     the person's AppData.
//
// The pure parts (here) are tested on every system; the Windows calls are
// in appsec_windows.go.
package appsec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// WebView2EnvPrefix starts every environment variable WebView2 reads
// (WEBVIEW2_BROWSER_EXECUTABLE_FOLDER, WEBVIEW2_USER_DATA_FOLDER,
// WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, WEBVIEW2_RELEASE_CHANNEL_PREFERENCE,
// WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER, ...). Windows compares variable names
// ignoring case, so this does too.
const WebView2EnvPrefix = "WEBVIEW2_"

// ScrubWebView2Env splits environ ("NAME=value" entries, as os.Environ and
// a Windows environment block have them) into what to keep and the names of
// the WEBVIEW2_* variables taken out. Entries Windows keeps for drive
// letters ("=C:=C:\x") are kept.
func ScrubWebView2Env(environ []string) (keep []string, removed []string) {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if len(name) >= len(WebView2EnvPrefix) && strings.EqualFold(name[:len(WebView2EnvPrefix)], WebView2EnvPrefix) {
			removed = append(removed, name)
			continue
		}
		keep = append(keep, kv)
	}
	return keep, removed
}

// The machine-wide Evergreen WebView2 runtime: its client ID in EdgeUpdate
// (HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{...}), and the
// folder it always lives in, under Program Files (x86) even on 64-bit and
// Arm64 Windows.
const (
	EvergreenClientKey = `SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
	EvergreenSubdir    = `Microsoft\EdgeWebView\Application`
)

var (
	versionRe = regexp.MustCompile(`^[0-9]{1,5}(\.[0-9]{1,5}){3}$`)
	driveRe   = regexp.MustCompile(`^[A-Za-z]:\\`)

	ErrUntrustedRuntime = errors.New("WebView2 runtime is not in a trusted place")
)

// RuntimeDir is where the machine-wide runtime of version pv is, given the
// "location" EdgeUpdate recorded for it.
func RuntimeDir(location, pv string) string {
	return strings.TrimRight(location, `\`) + `\` + pv
}

// ValidateRuntimeDir checks, from the path alone, that dir is
// <root>\Microsoft\EdgeWebView\Application\<version> for one of the Program
// Files folders in roots: absolute, on a drive (no network share, no \\?\
// prefix), nothing that could resolve elsewhere ("..", short 8.3 names,
// alternate streams). Whether those folders really are admin-owned is
// checked on disk by the Windows side.
func ValidateRuntimeDir(dir string, roots []string) error {
	bad := func(why string) error { return fmt.Errorf("%w: %s (%s)", ErrUntrustedRuntime, dir, why) }
	if err := cleanWinPath(dir); err != nil {
		return bad(err.Error())
	}
	for _, root := range roots {
		root = strings.TrimRight(root, `\`)
		if root == "" || cleanWinPath(root) != nil {
			continue
		}
		prefix := root + `\` + EvergreenSubdir + `\`
		if len(dir) <= len(prefix) || !strings.EqualFold(dir[:len(prefix)], prefix) {
			continue
		}
		if !versionRe.MatchString(dir[len(prefix):]) {
			return bad("not a version folder")
		}
		return nil
	}
	return bad("not under Program Files")
}

// cleanWinPath accepts only plain absolute Windows paths: X:\a\b, with no
// empty, "." or ".." parts, no "~" (8.3 short names), no ":" past the drive
// (alternate data streams) and no parts ending in a dot or a space (which
// Windows silently drops).
func cleanWinPath(p string) error {
	if !driveRe.MatchString(p) {
		return errors.New("not an absolute path on a drive")
	}
	for _, part := range strings.Split(p[3:], `\`) {
		switch {
		case part == "" || part == "." || part == "..":
			return errors.New("empty or relative part")
		case strings.ContainsAny(part, `~:/*?"<>|`):
			return errors.New("short name or odd character")
		case strings.HasSuffix(part, ".") || strings.HasSuffix(part, " "):
			return errors.New("part ending in a dot or space")
		}
	}
	return nil
}

// Well-known accounts trusted to own and write the runtime's folders and
// ABA's data folder.
const (
	SIDSystem           = "S-1-5-18"
	SIDAdministrators   = "S-1-5-32-544"
	SIDTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// TrustedSID reports whether sid is one of the accounts above.
func TrustedSID(sid string) bool {
	switch sid {
	case SIDSystem, SIDAdministrators, SIDTrustedInstaller:
		return true
	}
	return false
}

// ACE is one entry of a file's access list, reduced to what matters here.
type ACE struct {
	Allow       bool   // an allow entry (deny entries only take rights away)
	InheritOnly bool   // applies to things created inside, not to this object
	Mask        uint32 // the rights
	SID         string // who
}

// Rights that let someone change a file or folder, or what's in it, or who
// may: write/add a file, append/add a folder, delete children, delete,
// change the access list or the owner, and the generic forms.
const writeRights = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

// UntrustedWriters lists who, other than the trusted accounts, may change
// an object with this owner and access list (nil dacl entries = none; a
// missing access list, which lets everyone in, is the caller's to reject).
// An untrusted owner counts: owners can always rewrite the access list.
func UntrustedWriters(owner string, aces []ACE) []string {
	var out []string
	if !TrustedSID(owner) {
		out = append(out, owner+" (owner)")
	}
	for _, a := range aces {
		if !a.Allow || a.InheritOnly || a.Mask&writeRights == 0 || TrustedSID(a.SID) {
			continue
		}
		out = append(out, fmt.Sprintf("%s (0x%x)", a.SID, a.Mask))
	}
	return out
}

var alertIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidAlertID reports whether id can be an alert's ID: the only thing the
// service hands the app on its command line (the app reads the alert itself
// from the admin-only alerts folder).
func ValidAlertID(id string) bool { return alertIDRe.MatchString(id) && !strings.Contains(id, "..") }
