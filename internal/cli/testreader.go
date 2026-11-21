package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The fake stealer for `aba test` runs from your Temp folder, where real ones
// do. But `aba test` runs as administrator, and Temp is yours to write to: a
// program running as you could swap that file between ABA writing it and
// starting it, and have its own code started with admin rights.
//
// So the file gets a name nobody can guess, is created fresh, is checked
// after it's written, and is kept open in a way that forbids changing,
// renaming or deleting it until it's running. And it's started the way a real
// stealer runs: without admin rights. Even a swapped file would gain nothing.

// testReader is the running fake stealer.
type testReader struct {
	Path string
	PID  uint32
	As   string // how it was started
	proc windows.Handle
	lock windows.Handle // keeps the file from being touched while it runs
}

// startTestReader writes a copy of this program (self) into Temp and starts
// it as `test-reader <target>`.
func startTestReader(self []byte, target string) (*testReader, error) {
	name := make([]byte, 8)
	if _, err := rand.Read(name); err != nil {
		return nil, err
	}
	path := filepath.Join(os.TempDir(), "aba-test-"+hex.EncodeToString(name)+".exe")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// CREATE_NEW: fails if anything is already there.
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(self); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	f.Close()

	// Reopen for reading, sharing only reads: from here until this handle is
	// closed the file can't be written, renamed or deleted. Then make sure it
	// still is what was written (it was closed for a moment in between).
	lock, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("reopen %s: %w", path, err)
	}
	r := &testReader{Path: path, lock: lock}
	check := os.NewFile(uintptr(dupHandle(lock)), path)
	got, err := io.ReadAll(io.LimitReader(check, int64(len(self))+1))
	check.Close()
	if err != nil || !bytes.Equal(got, self) {
		r.Close()
		return nil, fmt.Errorf("%s was changed by another program before it could be started: not running it", path)
	}

	cmdline := syscall.EscapeArg(path) + " test-reader " + syscall.EscapeArg(target)
	// Without admin rights, the way a real stealer runs: with the desktop's
	// own token where there is a desktop, else with this one's filtered down.
	// If neither works (unusual token setup), as we are: the file is locked
	// and verified, so that's still safe.
	var errs []string
	for _, how := range []func(string) error{r.startAsDesktop, r.startFiltered, r.startAsIs} {
		err := how(cmdline)
		if err == nil {
			return r, nil
		}
		errs = append(errs, err.Error())
	}
	r.Close()
	return nil, fmt.Errorf("start the fake stealer: %s", strings.Join(errs, "; "))
}

// dupHandle gives a second handle to the same open file, so one can be
// wrapped in an os.File (and closed by it) while the other keeps the lock.
func dupHandle(h windows.Handle) windows.Handle {
	var d windows.Handle
	cur := windows.CurrentProcess()
	if windows.DuplicateHandle(cur, h, cur, &d, 0, false, windows.DUPLICATE_SAME_ACCESS) != nil {
		return 0
	}
	return d
}

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken   = advapi32.NewProc("CreateRestrictedToken")
	procCreateProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
	user32                      = windows.NewLazySystemDLL("user32.dll")
	procGetShellWindow          = user32.NewProc("GetShellWindow")
	procGetWindowThreadProcess  = user32.NewProc("GetWindowThreadProcessId")
)

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

// unelevated returns a copy of this process's token the way Windows makes
// one for a non-elevated program of an administrator: the Administrators
// group only counts for "deny", privileges are gone, integrity is medium.
func unelevated() (windows.Token, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	const luaToken = 0x4
	var lua windows.Token
	if r, _, e := procCreateRestrictedToken.Call(uintptr(tok), luaToken, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&lua))); r == 0 {
		return 0, fmt.Errorf("restricted token: %w", e)
	}
	if err := ownedByUser(lua); err != nil {
		lua.Close()
		return 0, err
	}
	medium, err := windows.StringToSid("S-1-16-8192") // Mandatory Label\Medium
	if err != nil {
		lua.Close()
		return 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(lua, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+windows.GetLengthSid(medium)); err != nil {
		lua.Close()
		return 0, err
	}
	return lua, nil
}

// desktopToken is a copy of the token the desktop (Explorer) runs with: what
// a program you double-click gets. Only when this process is elevated: the
// point is to shed admin rights, and using another process's token takes them.
func desktopToken() (windows.Token, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return 0, fmt.Errorf("not elevated: nothing to shed")
	}
	hwnd, _, _ := procGetShellWindow.Call()
	if hwnd == 0 {
		return 0, fmt.Errorf("no desktop in this session")
	}
	var pid uint32
	procGetWindowThreadProcess.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
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

func (r *testReader) started(pi *windows.ProcessInformation, how string) error {
	windows.CloseHandle(pi.Thread)
	r.proc, r.PID, r.As = pi.Process, pi.ProcessId, how
	return nil
}

func (r *testReader) startAsDesktop(cmdline string) error {
	tok, err := desktopToken()
	if err != nil {
		return err
	}
	defer tok.Close()
	app, _ := windows.UTF16PtrFromString(r.Path)
	cmd, _ := windows.UTF16PtrFromString(cmdline)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if ok, _, e := procCreateProcessWithTokenW.Call(uintptr(tok), 0, uintptr(unsafe.Pointer(app)), uintptr(unsafe.Pointer(cmd)),
		windows.CREATE_NO_WINDOW, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi))); ok == 0 {
		return fmt.Errorf("with the desktop's token: %w", e)
	}
	return r.started(&pi, "with the desktop's token")
}

func (r *testReader) startFiltered(cmdline string) error {
	tok, err := unelevated()
	if err != nil {
		return err
	}
	defer tok.Close()
	app, _ := windows.UTF16PtrFromString(r.Path)
	cmd, _ := windows.UTF16PtrFromString(cmdline)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("with admin rights filtered out: %w", err)
	}
	return r.started(&pi, "with admin rights filtered out")
}

func (r *testReader) startAsIs(cmdline string) error {
	app, _ := windows.UTF16PtrFromString(r.Path)
	cmd, _ := windows.UTF16PtrFromString(cmdline)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, cmd, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		return err
	}
	return r.started(&pi, "as started")
}

// Close ends the fake stealer (if it's still there) and deletes its file.
func (r *testReader) Close() {
	if r.proc != 0 {
		windows.TerminateProcess(r.proc, 0)
		windows.WaitForSingleObject(r.proc, 5000)
		windows.CloseHandle(r.proc)
		r.proc = 0
	}
	if r.lock != 0 {
		windows.CloseHandle(r.lock)
		r.lock = 0
	}
	os.Remove(r.Path)
}
