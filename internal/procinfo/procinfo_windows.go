package procinfo

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Snapshot lists all processes.
func Snapshot() (map[uint32]Entry, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	out := map[uint32]Entry{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(h, &pe); err == nil; err = windows.Process32Next(h, &pe) {
		e := Entry{PID: pe.ProcessID, PPID: pe.ParentProcessID, Exe: windows.UTF16ToString(pe.ExeFile[:])}
		e.CreateTime, _ = CreateTime(pe.ProcessID)
		out[pe.ProcessID] = e
	}
	return out, nil
}

func open(pid uint32, access uint32) (windows.Handle, error) {
	return windows.OpenProcess(access, false, pid)
}

// CreateTime returns the process creation FILETIME as int64.
func CreateTime(pid uint32) (int64, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime), nil
}

// ImagePath returns the full path of the process executable.
func ImagePath(pid uint32) (string, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// CommandLine returns the process command line (Windows 8.1+).
func CommandLine(pid uint32) (string, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var need uint32
	buf := make([]byte, 4096)
	for i := 0; i < 3; i++ {
		err = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &need)
		if err == nil {
			break
		}
		if need > uint32(len(buf)) {
			buf = make([]byte, need)
			continue
		}
		return "", err
	}
	if err != nil {
		return "", err
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Buffer == nil || us.Length == 0 {
		return "", nil
	}
	return windows.UTF16ToString(unsafe.Slice(us.Buffer, us.Length/2)), nil
}

var (
	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProc = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProc  = ntdll.NewProc("NtResumeProcess")
)

const processSuspendResume = 0x0800

func ntCall(p *windows.LazyProc, pid uint32) error {
	h, err := open(pid, processSuspendResume)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	r, _, _ := p.Call(uintptr(h))
	if r != 0 {
		return fmt.Errorf("%s: NTSTATUS 0x%08x", p.Name, uint32(r))
	}
	return nil
}

func Suspend(pid uint32) error { return ntCall(procNtSuspendProc, pid) }
func Resume(pid uint32) error  { return ntCall(procNtResumeProc, pid) }

// Kill terminates a process.
func Kill(pid uint32) error {
	h, err := open(pid, windows.PROCESS_TERMINATE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 0xF1)
}

// Alive reports whether pid exists and (if createTime != 0) is the same process.
func Alive(pid uint32, createTime int64) bool {
	ct, err := CreateTime(pid)
	if err != nil {
		return false
	}
	if createTime != 0 && ct != createTime {
		return false
	}
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// BaseName is a case-preserving file name of a Windows path.
func BaseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(strings.ReplaceAll(p, "/", `\`))
}

// Integrity levels (the RID of the token's mandatory label).
const (
	IntegrityLow    = 0x1000
	IntegrityMedium = 0x2000
	IntegrityHigh   = 0x3000
	IntegritySystem = 0x4000
)

// IntegrityLevel returns the process token's integrity RID.
func IntegrityLevel(pid uint32) (uint32, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0, fmt.Errorf("no integrity level")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	c := sid.SubAuthorityCount()
	if c == 0 {
		return 0, fmt.Errorf("bad integrity SID")
	}
	return sid.SubAuthority(uint32(c) - 1), nil
}
