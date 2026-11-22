package session

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ActiveSessions lists the sessions someone is logged in to and using (not
// session 0, where services run).
func ActiveSessions() ([]uint32, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	var out []uint32
	for _, s := range unsafe.Slice(info, count) {
		if s.State == wtsActive && s.SessionID != 0 {
			out = append(out, s.SessionID)
		}
	}
	return out, nil
}

// Helper is a program the service runs in someone's session as itself
// (SYSTEM), talking to it through pipes.
type Helper struct {
	Session uint32
	PID     uint32
	In      *os.File // the helper's standard input
	Out     *os.File // its standard output (and errors)
	process windows.Handle
}

// StartSystem runs exe with args in session id, on that session's desktop,
// with no window, as SYSTEM: this service's own account, so that nothing the
// person (or anything running as them) starts can stop it, look inside it or
// put words in its mouth. Only for helpers that need the session itself (its
// clipboard, say) and must be beyond reach of the programs they watch.
func StartSystem(id uint32, exe string, args ...string) (*Helper, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &self); err != nil {
		return nil, err
	}
	defer self.Close()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &tok); err != nil {
		return nil, err
	}
	defer tok.Close()
	// Moving a token to another session takes SeTcbPrivilege, which SYSTEM has.
	enableTcb()
	if err := windows.SetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&id)), 4); err != nil {
		return nil, err
	}
	return startHelper(tok, id, `winsta0\default`, exe, args)
}

// StartAsUser runs exe with args as the person logged on to this process's
// session (with their everyday token, as their own programs run), on its
// desktop, with no window. For a SYSTEM helper (see StartSystem) that needs
// something done as the person: what it starts is within their reach, so
// it's only ever given work whose result can't hurt if it's tampered with.
func StartAsUser(exe string, args ...string) (*Helper, error) {
	var id uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id); err != nil {
		return nil, err
	}
	enableTcb() // WTSQueryUserToken takes SeTcbPrivilege
	var tok windows.Token
	if err := windows.WTSQueryUserToken(id, &tok); err != nil {
		return nil, err
	}
	defer tok.Close()
	return startHelper(tok, id, `winsta0\default`, exe, args)
}

// StartOn runs exe with args as this process, on desktop (station\desktop),
// with pipes for its input and output, like the helpers above. For tests.
func StartOn(desktop, exe string, args ...string) (*Helper, error) {
	var id uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id)
	return startHelper(0, id, desktop, exe, args)
}

// startHelper runs exe as tok (0: as this process), in session id, on
// desktop, with pipes for its input and output.
func startHelper(tok windows.Token, id uint32, desktop, exe string, args []string) (*Helper, error) {

	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, &sa, 0); err != nil {
		return nil, err
	}
	if err := windows.CreatePipe(&outR, &outW, &sa, 0); err != nil {
		windows.CloseHandle(inR)
		windows.CloseHandle(inW)
		return nil, err
	}
	// Ours: not inherited.
	windows.SetHandleInformation(inW, windows.HANDLE_FLAG_INHERIT, 0)
	windows.SetHandleInformation(outR, windows.HANDLE_FLAG_INHERIT, 0)
	closeAll := func() {
		for _, h := range []windows.Handle{inR, inW, outR, outW} {
			windows.CloseHandle(h)
		}
	}

	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeAll()
		return nil, err
	}
	defer al.Delete()
	inherit := []windows.Handle{inR, outW}
	if err := al.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil {
		closeAll()
		return nil, err
	}
	desk, _ := windows.UTF16PtrFromString(desktop)
	six := windows.StartupInfoEx{ProcThreadAttributeList: al.List()}
	six.Cb = uint32(unsafe.Sizeof(six))
	six.Desktop = desk
	six.Flags = windows.STARTF_USESTDHANDLES
	six.StdInput, six.StdOutput, six.StdErr = inR, outW, outW

	cmdline := syscall.EscapeArg(exe)
	for _, a := range args {
		cmdline += " " + syscall.EscapeArg(a)
	}
	cl, _ := windows.UTF16PtrFromString(cmdline)
	app, _ := windows.UTF16PtrFromString(exe)
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT)
	if tok == 0 {
		err = windows.CreateProcess(app, cl, nil, nil, true, flags, nil, nil, &six.StartupInfo, &pi)
	} else {
		err = windows.CreateProcessAsUser(tok, app, cl, nil, nil, true, flags, nil, nil, &six.StartupInfo, &pi)
	}
	if err != nil {
		closeAll()
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(inR)
	windows.CloseHandle(outW)
	return &Helper{Session: id, PID: pi.ProcessId, process: pi.Process,
		In: os.NewFile(uintptr(inW), "helper stdin"), Out: os.NewFile(uintptr(outR), "helper stdout")}, nil
}

func enableTcb() {
	var tok windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok) != nil {
		return
	}
	defer tok.Close()
	var luid windows.LUID
	name, _ := windows.UTF16PtrFromString("SeTcbPrivilege")
	if windows.LookupPrivilegeValue(nil, name, &luid) != nil {
		return
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// Process is the helper's process handle, to wait on. It's the Helper's:
// don't close it.
func (h *Helper) Process() windows.Handle { return h.process }

// Exited reports whether the helper has ended.
func (h *Helper) Exited() bool {
	ev, err := windows.WaitForSingleObject(h.process, 0)
	return err != nil || ev == windows.WAIT_OBJECT_0
}

// Stop asks the helper to end, by closing its input, and kills it if it
// hasn't within a few seconds.
func (h *Helper) Stop() {
	h.In.Close()
	if ev, _ := windows.WaitForSingleObject(h.process, 5000); ev != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(h.process, 1)
	}
	h.Out.Close()
	windows.CloseHandle(h.process)
}
