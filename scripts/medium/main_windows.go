// Command medium launches a program at medium integrity, i.e. as an ordinary,
// non-admin process, from an elevated shell, and prints its PID.
//
// CI-only helper: GitHub's runners run everything as administrator, but real
// stealers run as the normal user. The e2e test uses this to launch its fake
// stealers realistically. Not part of ABA.
//
//	medium.exe "C:\path\to\program.exe" args...
//
// With -lua first, the program also loses its administrator membership (the
// token Windows gives a non-elevated program of an admin account), for checks
// of what a program without admin rights can read.
//
// With -shell first, it runs with the desktop's own token (Explorer's): on a
// PC someone is signed in to, that's exactly what a program they double-click
// gets.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var lua, shell bool

func main() {
	for len(os.Args) > 1 && (os.Args[1] == "-lua" || os.Args[1] == "-shell") {
		lua, shell = lua || os.Args[1] == "-lua", shell || os.Args[1] == "-shell"
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	// medium -raw <program> <command line>: the command line is passed as is,
	// with single quotes turned into double quotes (for programs like find.exe
	// that insist on quotes, which PowerShell 5 mangles).
	if len(os.Args) == 4 && os.Args[1] == "-raw" {
		if err := run(os.Args[2], strings.ReplaceAll(os.Args[3], "'", "\"")); err != nil {
			fmt.Fprintln(os.Stderr, "medium:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: medium <program> [args...]")
		os.Exit(2)
	}
	parts := make([]string, len(os.Args)-1)
	for i, a := range os.Args[1:] {
		parts[i] = syscall.EscapeArg(a)
	}
	if err := run(os.Args[1], strings.Join(parts, " ")); err != nil {
		fmt.Fprintln(os.Stderr, "medium:", err)
		os.Exit(1)
	}
}

// ownedByUser makes the token's user the owner of what a process running
// with it creates, and gives that user access to it. A token with the
// administrators group filtered out still names that group as default owner,
// which it may no longer be: every object the process then creates (its own
// threads included) is refused, and the program dies before it does anything.
func ownedByUser(tok windows.Token) error {
	u, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	owner := struct{ Owner *windows.SID }{u.User.Sid}
	const tokenOwner, tokenDefaultDacl = 4, 6
	if err := windows.SetTokenInformation(tok, tokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
		return fmt.Errorf("token owner: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	entry := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(sid)}}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry(u.User.Sid), entry(system)}, nil)
	if err != nil {
		return err
	}
	dacl := struct{ DefaultDacl *windows.ACL }{acl}
	if err := windows.SetTokenInformation(tok, tokenDefaultDacl, (*byte)(unsafe.Pointer(&dacl)), uint32(unsafe.Sizeof(dacl))); err != nil {
		return fmt.Errorf("token default permissions: %w", err)
	}
	return nil
}

// shellToken is a copy of the token Explorer (the desktop) runs with.
func shellToken() (windows.Token, error) {
	user32 := windows.NewLazySystemDLL("user32.dll")
	hwnd, _, _ := user32.NewProc("GetShellWindow").Call()
	if hwnd == 0 {
		return 0, fmt.Errorf("no desktop shell in this session")
	}
	var pid uint32
	user32.NewProc("GetWindowThreadProcessId").Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	ph, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(ph)
	var tok windows.Token
	if err := windows.OpenProcessToken(ph, windows.TOKEN_DUPLICATE, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	var dup windows.Token
	const access = windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_DUPLICATE | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID
	if err := windows.DuplicateTokenEx(tok, access, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, err
	}
	return dup, nil
}

func runShell(app, cmdline string) error {
	tok, err := shellToken()
	if err != nil {
		return err
	}
	defer tok.Close()
	appp, _ := windows.UTF16PtrFromString(app)
	cmd, _ := windows.UTF16PtrFromString(cmdline)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	r, _, e := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithTokenW").Call(uintptr(tok), 0,
		uintptr(unsafe.Pointer(appp)), uintptr(unsafe.Pointer(cmd)), windows.CREATE_NO_WINDOW, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return fmt.Errorf("create process with the desktop's token: %w", e)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	fmt.Println(pi.ProcessId)
	return nil
}

func run(app, cmdline string) error {
	if shell {
		return runShell(app, cmdline)
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY, &tok); err != nil {
		return fmt.Errorf("open token: %w", err)
	}
	defer tok.Close()
	var dup windows.Token
	if lua {
		const luaToken = 0x4
		if r, _, e := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(uintptr(tok), luaToken, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&dup))); r == 0 {
			return fmt.Errorf("restricted token: %w", e)
		}
	} else if err := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return fmt.Errorf("duplicate token: %w", err)
	}
	defer dup.Close()
	if lua {
		if err := ownedByUser(dup); err != nil {
			return err
		}
	}

	medium, err := windows.StringToSid("S-1-16-8192") // Mandatory Label\Medium
	if err != nil {
		return err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(dup, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+windows.GetLengthSid(medium)); err != nil {
		return fmt.Errorf("lower integrity: %w", err)
	}

	appp, _ := windows.UTF16PtrFromString(app)
	cmd, _ := windows.UTF16PtrFromString(cmdline)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(dup, appp, cmd, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("create process: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	fmt.Println(pi.ProcessId)
	return nil
}
