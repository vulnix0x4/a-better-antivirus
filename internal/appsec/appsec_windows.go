package appsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// ScrubProcessEnv takes every WEBVIEW2_* variable out of this process's
// environment (and so out of the browser engine's, which inherits it), then
// sets the documented ones to their neutral values: WebView2 checks whether
// a variable exists, not whether it's empty, before falling back to registry
// overrides, so empty beats absent. (go-webview2 does the same on its own;
// this doesn't rely on it.) Call it first thing, before anything starts
// WebView2. It returns the names that had a value other than the neutral
// one: what someone planted. (go-webview2's package init already blanks
// the five documented variables before main runs, so in the app this
// reports only the others; all are gone either way.)
func ScrubProcessEnv() []string {
	var planted []string
	_, removed := ScrubWebView2Env(os.Environ())
	for _, name := range removed {
		if v := os.Getenv(name); v != neutralEnv[strings.ToUpper(name)] {
			planted = append(planted, name)
		}
		os.Unsetenv(name)
	}
	for name, v := range neutralEnv {
		os.Setenv(name, v)
	}
	return planted
}

var neutralEnv = map[string]string{
	"WEBVIEW2_BROWSER_EXECUTABLE_FOLDER":    "",
	"WEBVIEW2_USER_DATA_FOLDER":             "",
	"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "",
	"WEBVIEW2_RELEASE_CHANNEL_PREFERENCE":   "0",
	"WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER":     "",
}

// ResolveRuntime finds the machine-wide Evergreen WebView2 runtime from
// HKLM (which only administrators can change) and checks it on disk: under
// Program Files, every folder from Program Files down to it, its
// msedgewebview2.exe and the EmbeddedBrowserWebView.dll this process will
// load must be owned by SYSTEM, Administrators or TrustedInstaller, and
// writable by nobody else. It returns the runtime's folder, to pin WebView2
// to (never the per-user runtime, nor whatever the environment names).
func ResolveRuntime() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, EvergreenClientKey, registry.QUERY_VALUE|registry.WOW64_32KEY)
	if err != nil {
		return "", fmt.Errorf("machine-wide WebView2 runtime not installed: %w", err)
	}
	defer k.Close()
	location, _, err := k.GetStringValue("location")
	if err != nil {
		return "", fmt.Errorf("WebView2 runtime: no location: %w", err)
	}
	pv, _, err := k.GetStringValue("pv")
	if err != nil || pv == "" || pv == "0.0.0.0" {
		return "", fmt.Errorf("WebView2 runtime: no version (%v)", err)
	}
	dir := RuntimeDir(location, pv)
	roots := programFilesRoots()
	if err := ValidateRuntimeDir(dir, roots); err != nil {
		return "", err
	}
	root := ""
	for _, r := range roots {
		r = strings.TrimRight(r, `\`)
		if len(dir) > len(r) && strings.EqualFold(dir[:len(r)+1], r+`\`) {
			root = dir[:len(r)]
			break
		}
	}
	// Every folder from Program Files down to the runtime, then the files.
	check := []string{root}
	p := root
	for _, part := range strings.Split(dir[len(root)+1:], `\`) {
		p += `\` + part
		check = append(check, p)
	}
	check = append(check, dir+`\msedgewebview2.exe`, dir+`\EBWebView\`+ebArch()+`\EmbeddedBrowserWebView.dll`)
	for _, c := range check {
		if err := CheckAdminOnly(c); err != nil {
			return "", fmt.Errorf("%w: %v", ErrUntrustedRuntime, err)
		}
	}
	return dir, nil
}

func ebArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	case "386":
		return "x86"
	}
	return "x64"
}

// programFilesRoots are the Program Files folders, from HKLM (machine
// settings only administrators can change), not from environment variables.
// Not from SHGetKnownFolderPath either: called on the app's main thread,
// which Wails locks and starts GDI+ on before main runs, it never returns.
func programFilesRoots() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	var out []string
	for _, name := range []string{"ProgramFilesDir (x86)", "ProgramFilesDir"} {
		if p, _, err := k.GetStringValue(name); err == nil && p != "" {
			out = append(out, p)
		}
	}
	return out
}

// CheckAdminOnly fails unless path exists, isn't a link or junction, and
// only SYSTEM, Administrators and TrustedInstaller own it or may change it.
func CheckAdminOnly(path string) error {
	u, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(u)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: is a link or junction", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: no owner", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s: no access list (open to everyone)", path)
	}
	aces, err := readACEs(dacl)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if w := UntrustedWriters(owner.String(), aces); len(w) > 0 {
		return fmt.Errorf("%s: may be changed by %s", path, strings.Join(w, ", "))
	}
	return nil
}

func readACEs(acl *windows.ACL) ([]ACE, error) {
	var out []ACE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &a); err != nil {
			return nil, err
		}
		e := ACE{Mask: uint32(a.Mask), InheritOnly: a.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0}
		switch a.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			e.Allow = true
		case windows.ACCESS_DENIED_ACE_TYPE:
		default:
			// Object and callback entries: none are expected on these
			// folders, so don't try to read them. Treat as a refusal.
			return nil, fmt.Errorf("unexpected access entry type %d", a.Header.AceType)
		}
		e.SID = (*windows.SID)(unsafe.Pointer(&a.SidStart)).String()
		out = append(out, e)
	}
	return out, nil
}

// adminOnlySDDL: SYSTEM and Administrators, nobody else, not inherited from
// ProgramData (where everyone may create folders).
const adminOnlySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// PrepareAppDir creates the app's folder in ABA's data folder
// (paths.AppDir) admin-only from the start if it's missing, and refuses one
// someone else could have made or could change (a person can create
// folders in ProgramData).
func PrepareAppDir() (string, error) {
	for _, d := range []string{paths.DataDir(), paths.AppDir()} {
		if err := mkdirAdminOnly(d); err != nil {
			return "", err
		}
		if err := CheckAdminOnly(d); err != nil {
			return "", err
		}
	}
	return paths.AppDir(), nil
}

func mkdirAdminOnly(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(adminOnlySDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	u, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(u, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return nil
}

// WebViewDir is the app's WebView2 profile folder, in the person's own
// LocalAppData, elevated or not. WebView2 starts its browser and renderer
// processes de-elevated, with the person's ordinary (medium integrity)
// token, even when the app hosting it is elevated (by design, per
// Microsoft; seen with runtime 158): those processes can't write to an
// admin-only folder, and WebView2 then stops at a "can't read and write to
// its data directory" box. The profile is therefore as much the person's
// (and their programs') as the browser processes are; nothing in it is
// trusted by the elevated app.
func WebViewDir() string {
	base, err := os.UserCacheDir() // %LocalAppData%
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "ABA", "webview")
}

// IsElevated reports whether this process has an elevated (full)
// administrator token.
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// RelaunchElevated starts this program again with args, asking Windows for
// administrator rights (the UAC prompt on the secure desktop).
func RelaunchElevated(args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var q []string
	for _, a := range args {
		q = append(q, syscall.EscapeArg(a))
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(q, " "))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_SHOWNORMAL)
}

var (
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procCreateBoundaryDescriptorW  = kernel32.NewProc("CreateBoundaryDescriptorW")
	procAddSIDToBoundaryDescriptor = kernel32.NewProc("AddSIDToBoundaryDescriptor")
	procDeleteBoundaryDescriptor   = kernel32.NewProc("DeleteBoundaryDescriptor")
	procCreatePrivateNamespaceW    = kernel32.NewProc("CreatePrivateNamespaceW")
	procOpenPrivateNamespaceW      = kernel32.NewProc("OpenPrivateNamespaceW")
	procClosePrivateNamespace      = kernel32.NewProc("ClosePrivateNamespace")
)

// ErrAlreadyRunning: another elevated copy of the app has this session.
var ErrAlreadyRunning = errors.New("ABA is already open")

// Instance holds the single-instance lock until Release.
type Instance struct {
	ns, mutex windows.Handle
}

// Release lets another copy start.
func (i *Instance) Release() {
	windows.CloseHandle(i.mutex)
	procClosePrivateNamespace.Call(uintptr(i.ns), 0)
}

// SingleInstance takes the app's lock for this session: a mutex in a
// private object namespace whose boundary is the Administrators group.
// Only an elevated administrator can create or open that namespace, so a
// program running as the person can neither take the name first (to keep
// ABA from opening) nor pretend to be the open copy. Returns
// ErrAlreadyRunning when another copy holds it.
func SingleInstance() (*Instance, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	bname, _ := windows.UTF16PtrFromString("ABA-app-boundary")
	bd, _, e := procCreateBoundaryDescriptorW.Call(uintptr(unsafe.Pointer(bname)), 0)
	if bd == 0 {
		return nil, fmt.Errorf("CreateBoundaryDescriptor: %w", e)
	}
	// AddSIDToBoundaryDescriptor may move the descriptor (it takes &bd):
	// delete whatever bd is at the end, not the first one.
	defer func() { procDeleteBoundaryDescriptor.Call(bd) }()
	if r, _, e := procAddSIDToBoundaryDescriptor.Call(uintptr(unsafe.Pointer(&bd)), uintptr(unsafe.Pointer(admins))); r == 0 {
		return nil, fmt.Errorf("AddSIDToBoundaryDescriptor: %w", e)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	alias, _ := windows.UTF16PtrFromString("ABAApp")
	ns, _, e := procCreatePrivateNamespaceW.Call(uintptr(unsafe.Pointer(&sa)), bd, uintptr(unsafe.Pointer(alias)))
	if ns == 0 {
		if !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
			return nil, fmt.Errorf("CreatePrivateNamespace: %w", e)
		}
		ns, _, e = procOpenPrivateNamespaceW.Call(bd, uintptr(unsafe.Pointer(alias)))
		if ns == 0 {
			return nil, fmt.Errorf("OpenPrivateNamespace: %w", e)
		}
	}
	var sess uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sess)
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`ABAApp\app-session-%d`, sess))
	h, err := windows.CreateMutex(&sa, false, name)
	if h == 0 {
		procClosePrivateNamespace.Call(ns, 0)
		return nil, fmt.Errorf("CreateMutex: %w", err)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		procClosePrivateNamespace.Call(ns, 0)
		return nil, ErrAlreadyRunning
	}
	return &Instance{ns: windows.Handle(ns), mutex: h}, nil
}
