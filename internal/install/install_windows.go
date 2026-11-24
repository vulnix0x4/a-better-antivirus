package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// CurrentUser resolves the user being protected (whoever ran the installer).
func CurrentUser() (config.UserInfo, error) {
	sid, name, err := winsec.CurrentUserSID()
	if err != nil {
		return config.UserInfo{}, err
	}
	kf := func(id *windows.KNOWNFOLDERID) string {
		p, _ := windows.KnownFolderPath(id, 0)
		return p
	}
	u := config.UserInfo{
		SID: sid, Name: name,
		Profile:        kf(windows.FOLDERID_Profile),
		Desktop:        kf(windows.FOLDERID_Desktop),
		Documents:      kf(windows.FOLDERID_Documents),
		Downloads:      kf(windows.FOLDERID_Downloads),
		LocalAppData:   kf(windows.FOLDERID_LocalAppData),
		RoamingAppData: kf(windows.FOLDERID_RoamingAppData),
	}
	if u.Profile == "" {
		return u, errors.New("could not resolve your user profile folder")
	}
	return u, nil
}

// cleanupSteps run right after the first check: clearing away what earlier
// generations of ABA left behind.
func cleanupSteps() []Step {
	return []Step{{Name: "Cleaning up older versions", Soft: true, Run: migrateLegacy}}
}

// detectionSteps switch on what Windows needs to notice a bait being read:
// the "File System" audit policy (and remember how it was, for uninstall).
func detectionSteps() []Step {
	return []Step{{Name: "Turning on Windows file auditing", Run: func() (string, error) {
		err := config.UpdateState(func(st *config.State) error {
			if st.AuditOriginal == nil {
				cur, err := winsec.FileSystemAudit()
				if err != nil {
					return err
				}
				st.AuditOriginal = &cur
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		_, err = winsec.EnsureFileSystemAudit()
		return "how ABA sees who opens a bait", err
	}}}
}

// restoreSteps undo detectionSteps on uninstall, and take the flight
// recorder's audit rules off the folders of your real data.
func restoreSteps() []Step {
	return []Step{{Name: "Restoring Windows audit settings", Soft: true, Run: func() (string, error) {
		st, err := config.LoadState()
		if err != nil || st.AuditOriginal == nil {
			return "left as is", nil
		}
		return "", winsec.SetFileSystemAudit(*st.AuditOriginal)
	}}, {Name: "Removing the flight recorder's audit rules", Soft: true, Run: func() (string, error) {
		st, err := config.LoadState()
		if err != nil {
			return "", err
		}
		return ClearRecorderRules(st.RecorderDirs)
	}}}
}

// ClearRecorderRules takes the flight recorder's audit rule off dirs (and
// only that rule: see winsec.ClearRecorderAudit).
func ClearRecorderRules(dirs []string) (string, error) {
	n, failed := 0, 0
	var first error
	for _, d := range dirs {
		if err := winsec.ClearRecorderAudit(d); err != nil {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
				continue
			}
			failed++
			if first == nil {
				first = fmt.Errorf("%s: %w", d, err)
			}
			continue
		}
		n++
	}
	if first != nil {
		return fmt.Sprintf("%d folder(s) done, %d not", n, failed), first
	}
	return fmt.Sprintf("%d folder(s)", n), nil
}

// deleteProgramFiles removes the install folder on uninstall, including the
// program that's doing the uninstalling.
func deleteProgramFiles() (string, error) {
	self, _ := os.Executable()
	if paths.Under(self, paths.InstallDir()) {
		// Can't delete ourselves while running: let cmd do it after we exit.
		return "finishes after this window closes", deleteDirAfterExit(paths.InstallDir())
	}
	// Close leftover ABA processes (e.g. an alert popup nobody clicked).
	if snap, err := procinfo.Snapshot(); err == nil {
		for pid := range snap {
			if img, err := procinfo.ImagePath(pid); err == nil && paths.Under(img, paths.InstallDir()) && pid != uint32(os.Getpid()) {
				procinfo.Kill(pid)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := os.RemoveAll(paths.InstallDir()); err != nil {
		// Something still holds a file: delete what's left at next reboot.
		// Register children before their folders so the folders are empty by then.
		var left []string
		filepath.Walk(paths.InstallDir(), func(p string, _ os.FileInfo, _ error) error {
			left = append(left, p)
			return nil
		})
		for i := len(left) - 1; i >= 0; i-- {
			scheduleDelete(left[i])
		}
		return "some files were in use; they'll be deleted at the next restart", nil
	}
	return "", nil
}

// deleteDirAfterExit removes dir once nothing in it is running any more. A
// program can't delete its own file, so a hidden cmd.exe does it: it tries
// about once a second for a quarter of an hour (the window may be waiting on
// "Press Enter to close") and stops as soon as the folder is gone.
func deleteDirAfterExit(dir string) error {
	if strings.ContainsAny(dir, `"%&|<>^`) {
		return fmt.Errorf("not deleting %s: unexpected characters in the path", dir)
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(sys, "cmd.exe"))
	// cmd.exe has its own quoting rules, so the command line is given as is:
	// Go's usual escaping (\") would hand rmdir a path it can't find.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
		CmdLine: `cmd.exe /d /c "for /l %i in (1,1,900) do @(ping -n 2 127.0.0.1 >nul & rmdir /s /q "` + dir +
			`" 2>nul & if not exist "` + dir + `" exit)"`,
	}
	cmd.Dir = sys // not the folder being deleted
	return cmd.Start()
}

// scheduleDelete deletes p now, or at the next restart if it's still in use.
func scheduleDelete(p string) {
	if os.Remove(p) == nil {
		return
	}
	from, _ := windows.UTF16PtrFromString(p)
	windows.MoveFileEx(from, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

func migrateLegacy() (string, error) {
	var did []string
	for _, tn := range []string{`\Honeypot\Responder`, `\Honeypot\Notify`} {
		cmd := exec.Command("schtasks.exe", "/Delete", "/TN", tn, "/F")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if cmd.Run() == nil {
			did = append(did, "task "+tn)
		}
	}
	exec.Command("schtasks.exe", "/Delete", "/TN", `\Honeypot`, "/F").Run()
	legacy := filepath.Join(os.Getenv("ProgramFiles"), "Honeypot")
	if _, err := os.Stat(legacy); err == nil {
		if err := os.RemoveAll(legacy); err == nil {
			did = append(did, legacy)
		}
	}
	if len(did) == 0 {
		return "nothing to clean up", nil
	}
	return "removed " + strings.Join(did, ", ") + " (its baits are adopted)", nil
}

// ---- PATH ----

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

func AddToPath(dir string) error      { return editPath(dir, true) }
func RemoveFromPath(dir string) error { return editPath(dir, false) }

func editPath(dir string, add bool) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	cur, typ, err := k.GetStringValue("Path")
	if err != nil {
		return err
	}
	var parts []string
	found := false
	for _, p := range strings.Split(cur, ";") {
		if p == "" {
			continue
		}
		if paths.Same(strings.TrimRight(p, `\`), strings.TrimRight(dir, `\`)) {
			found = true
			if !add {
				continue
			}
		}
		parts = append(parts, p)
	}
	if add && found || !add && !found {
		return nil
	}
	if add {
		parts = append(parts, dir)
	}
	val := strings.Join(parts, ";")
	if typ == registry.EXPAND_SZ {
		err = k.SetExpandStringValue("Path", val)
	} else {
		err = k.SetStringValue("Path", val)
	}
	if err != nil {
		return err
	}
	broadcastEnvChange()
	return nil
}

func broadcastEnvChange() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	p := user32.NewProc("SendMessageTimeoutW")
	env, _ := windows.UTF16PtrFromString("Environment")
	var res uintptr
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x1A, 0x2
	p.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 3000, uintptr(unsafe.Pointer(&res)))
}

// permissionSteps run once the service is started: whatever the person at
// the screen has to allow for it to protect (on macOS, Full Disk Access).
// Nothing on Windows.
func permissionSteps() []Step { return nil }
