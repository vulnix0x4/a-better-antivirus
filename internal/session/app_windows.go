package session

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vulnix0x4/a-better-antivirus/internal/appsec"
	"github.com/vulnix0x4/a-better-antivirus/internal/sysenv"
)

// AppLaunch is how the desktop app was started in one session. It holds the
// process open (to see whether it ended, and how): Close it.
type AppLaunch struct {
	Session uint32
	PID     uint32
	Pick    TokenPick
	proc    windows.Handle
}

// Exited reports whether the app has ended, and its exit code if so.
func (l AppLaunch) Exited() (bool, uint32) {
	if l.proc == 0 {
		return false, 0
	}
	if ev, err := windows.WaitForSingleObject(l.proc, 0); err != nil || ev != windows.WAIT_OBJECT_0 {
		return false, 0
	}
	var code uint32
	if windows.GetExitCodeProcess(l.proc, &code) != nil {
		return true, 1
	}
	return true, code
}

// Terminate ends the app (one that never showed its window).
func (l AppLaunch) Terminate() {
	if l.proc != 0 {
		windows.TerminateProcess(l.proc, 1)
	}
}

// Close lets go of the process.
func (l AppLaunch) Close() {
	if l.proc != 0 {
		windows.CloseHandle(l.proc)
	}
}

// LaunchApp starts the desktop app (exe, with args) on the desktop of every
// active session, from the service (SYSTEM, which holds SeTcbPrivilege):
// with the person's elevated token when they're an administrator (the
// linked token of their UAC-filtered one: no prompt, as SYSTEM may hand it
// out), with their own token otherwise (the app then shows its locked view).
// exe must be an absolute path to an admin-only location (the install
// folder); only an ID is ever passed in args, the app reads the rest itself.
func LaunchApp(exe string, args ...string) ([]AppLaunch, error) {
	if !filepath.IsAbs(exe) {
		return nil, fmt.Errorf("app path must be absolute: %s", exe)
	}
	ids, err := ActiveSessions()
	if err != nil {
		return nil, err
	}
	enableTcb()
	var out []AppLaunch
	var errs []error
	for _, id := range ids {
		l, err := launchAppIn(id, exe, args)
		if err != nil {
			errs = append(errs, fmt.Errorf("session %d: %w", id, err))
			continue
		}
		out = append(out, l)
	}
	return out, errors.Join(errs...)
}

func launchAppIn(sessionID uint32, exe string, args []string) (AppLaunch, error) {
	l := AppLaunch{Session: sessionID}
	var user windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &user); err != nil {
		return l, fmt.Errorf("WTSQueryUserToken: %w", err)
	}
	defer user.Close()
	tok, pick, err := appToken(user)
	if err != nil {
		return l, err
	}
	if tok != user {
		defer tok.Close()
	}
	l.Pick = pick

	env, err := appEnvironment(tok)
	if err != nil {
		return l, err
	}
	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	cmd, _ := windows.UTF16PtrFromString(strings.Join(parts, " "))
	app, _ := windows.UTF16PtrFromString(exe)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desk}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, &env[0], dir, &si, &pi); err != nil {
		return l, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	l.proc = pi.Process
	l.PID = pi.ProcessId
	return l, nil
}

// appToken picks the token for the app from the person's session token
// (see pickToken). For PickLinked it returns a new token the caller closes.
func appToken(user windows.Token) (windows.Token, TokenPick, error) {
	var typ uint32
	var n uint32
	if err := windows.GetTokenInformation(user, windows.TokenElevationType, (*byte)(unsafe.Pointer(&typ)), 4, &n); err != nil {
		return 0, 0, fmt.Errorf("token elevation type: %w", err)
	}
	groups, err := user.GetTokenGroups()
	if err != nil {
		return 0, 0, fmt.Errorf("token groups: %w", err)
	}
	var gs []tokenGroup
	for _, g := range groups.AllGroups() {
		gs = append(gs, tokenGroup{sid: g.Sid.String(), attrs: g.Attributes})
	}
	pick := pickToken(typ, adminEnabled(gs))
	if pick != PickLinked {
		return user, pick, nil
	}
	// With SeTcbPrivilege (SYSTEM) this is a primary token, usable to start
	// a process; without it, Windows hands out only an identification token.
	linked, err := user.GetLinkedToken()
	if err != nil {
		return 0, 0, fmt.Errorf("linked token: %w", err)
	}
	if !linked.IsElevated() {
		linked.Close()
		return 0, 0, errors.New("linked token is not elevated")
	}
	return linked, pick, nil
}

// appEnvironment is the person's environment for tok, as a UTF-16 block,
// minus WEBVIEW2_* (which the person may set in HKCU\Environment to steer
// the elevated app's browser engine), and with the machine's own Windows,
// Program Files and ProgramData folders, PATH, and the person's folders
// from the machine's list of profiles, whatever HKCU\Environment says
// (sysenv.Clean: an elevated app reading ABA's data from a folder the person
// chose is theirs to steer). The app cleans its own environment too.
func appEnvironment(tok windows.Token) ([]uint16, error) {
	env, err := tok.Environ(false)
	if err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}
	keep, _ := appsec.ScrubWebView2Env(env)
	keep = sysenv.Clean(keep, sysenv.Machine(), sysenv.TokenProfile(tok))
	var block []uint16
	for _, kv := range keep {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			continue // a NUL inside: drop it
		}
		block = append(block, u...)
	}
	return append(block, 0), nil
}
