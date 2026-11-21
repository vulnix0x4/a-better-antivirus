package config

// How Windows keeps ABA's data to itself: DPAPI for the secrets, access
// control lists on the data folder, and a named mutex for the state lock.

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// restrictSecrets leaves the secrets file to SYSTEM + Administrators only, no
// inheritance from the data dir.
func restrictSecrets(path string) error {
	return SetSDDL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
}

// SetSDDL applies a protected DACL from SDDL to a file or directory.
func SetSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

const cryptprotectLocalMachine = 0x4

func protect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		b = []byte("{}")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, cryptprotectLocalMachine|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return []byte("{}"), nil
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

const (
	// SYSTEM + Administrators: full. Nobody else, not even to read.
	privateSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// The public folder: Users may read.
	publicSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

// lockDir makes dir (and everything already in it) private, except for its
// public subfolder.
func lockDir(dir, public string) error {
	for _, d := range []string{dir, public} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := SetSDDL(dir, privateSDDL); err != nil {
		return err
	}
	return SetSDDL(public, publicSDDL)
}

// stateLockName is a machine-wide mutex shared by the service and the CLI.
var stateLockName = `Global\ABAStateLock`

// inProcess serialises goroutines within one process. Needed because a Windows
// mutex belongs to an OS *thread* and is re-entrant per thread: two goroutines
// that happen to run on the same thread would both "acquire" it.
var inProcess sync.Mutex

func lockState() (func(), error) {
	inProcess.Lock()
	// Pin this goroutine to its OS thread while holding the mutex: Go may
	// otherwise move it, and ReleaseMutex from a different thread fails
	// silently, leaving the lock stuck until every other caller times out.
	runtime.LockOSThread()
	fail := func(err error) (func(), error) {
		runtime.UnlockOSThread()
		inProcess.Unlock()
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString(stateLockName)
	// Explicit DACL: whichever of SYSTEM (service) or an elevated admin (CLI)
	// creates the mutex first, the other must be able to open it.
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)")
	if err != nil {
		return fail(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(sa, false, name)
	if err != nil && h == 0 {
		return fail(fmt.Errorf("state lock: %w", err))
	}
	ev, err := windows.WaitForSingleObject(h, 30_000)
	if err != nil || (ev != windows.WAIT_OBJECT_0 && ev != windows.WAIT_ABANDONED) {
		windows.CloseHandle(h)
		return fail(fmt.Errorf("state lock: timed out"))
	}
	return func() {
		windows.ReleaseMutex(h)
		windows.CloseHandle(h)
		runtime.UnlockOSThread()
		inProcess.Unlock()
	}, nil
}
