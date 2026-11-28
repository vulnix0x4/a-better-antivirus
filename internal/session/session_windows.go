package session

// On Windows the service runs as SYSTEM in session 0, which has no desktop, so
// popups must be launched into the users' sessions with their own tokens.

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const wtsActive = 0

// LaunchInActiveSessions runs exe with args as each active user (not elevated).
// It returns the number of sessions it launched into.
func LaunchInActiveSessions(exe string, args ...string) (int, error) {
	return LaunchWithInput(exe, nil, args...)
}

// LaunchWithInput is LaunchInActiveSessions with input on the program's
// standard input. That's how the service hands an alert to the popup: the
// alert files themselves are for administrators only, and a command line can
// be read by anything running as the same user.
func LaunchWithInput(exe string, input []byte, args ...string) (int, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	sessions := unsafe.Slice(info, count)
	n := 0
	var firstErr error
	for _, s := range sessions {
		if s.State != wtsActive || s.SessionID == 0 {
			continue
		}
		if err := launch(s.SessionID, exe, args, input); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("session %d: %w", s.SessionID, err)
			}
			continue
		}
		n++
	}
	return n, firstErr
}

// LaunchWithInputIn is LaunchWithInput for one session.
func LaunchWithInputIn(sessionID uint32, exe string, input []byte, args ...string) error {
	return launch(sessionID, exe, args, input)
}

func launch(sessionID uint32, exe string, args []string, input []byte) error {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	return start(tok, env, desk, exe, args, input)
}

// start runs exe with args under tok, with input (if not nil) on its
// standard input.
func start(tok windows.Token, env, desk *uint16, exe string, args []string, input []byte) error {
	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	cmd, _ := windows.UTF16PtrFromString(strings.Join(parts, " "))
	app, _ := windows.UTF16PtrFromString(exe)
	flags := uint32(windows.CREATE_NO_WINDOW)
	if env != nil {
		flags |= windows.CREATE_UNICODE_ENVIRONMENT
	}
	var pi windows.ProcessInformation

	if input == nil {
		si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desk}
		if err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, false, flags, env, nil, &si, &pi); err != nil {
			return err
		}
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		return nil
	}

	// A pipe whose read end, and nothing else of ours, the child inherits.
	var rd, wr windows.Handle
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&rd, &wr, &sa, uint32(len(input)+4096)); err != nil {
		return err
	}
	defer windows.CloseHandle(rd)
	if err := windows.SetHandleInformation(wr, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(wr)
		return err
	}
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		windows.CloseHandle(wr)
		return err
	}
	defer al.Delete()
	inherit := []windows.Handle{rd}
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), unsafe.Sizeof(inherit[0])); err != nil {
		windows.CloseHandle(wr)
		return err
	}
	six := windows.StartupInfoEx{ProcThreadAttributeList: al.List()}
	six.Cb = uint32(unsafe.Sizeof(six))
	six.Desktop = desk
	six.Flags = windows.STARTF_USESTDHANDLES
	six.StdInput = rd
	if err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, true, flags|windows.EXTENDED_STARTUPINFO_PRESENT, env, nil, &six.StartupInfo, &pi); err != nil {
		windows.CloseHandle(wr)
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	// The pipe holds the whole input, so this doesn't wait for the child.
	go func() {
		var n uint32
		windows.WriteFile(wr, input, &n, nil)
		windows.CloseHandle(wr)
	}()
	return nil
}
