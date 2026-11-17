// Package install puts ABA on the machine (and takes it off again).
// Every step is idempotent, so re-running install reconfigures in place.
package install

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"

	"github.com/vulnix0x4/a-better-antivirus/internal/baits"
	"github.com/vulnix0x4/a-better-antivirus/internal/canary"
	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
	"github.com/vulnix0x4/a-better-antivirus/internal/respond"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
	"github.com/vulnix0x4/a-better-antivirus/internal/winsec"
)

// Options chosen in the wizard (or flags).
type Options struct {
	Baits        []string // catalog IDs
	CustomBaits  []string // extra file paths
	Preset       string
	Responses    map[config.Tier][]config.Action // when Preset == "custom"
	LearningDays int
	Phone        config.PhoneConfig
	PhoneMinTier config.Tier
	CanaryEmail  string // non-empty: create canary tokens
	CleanRecent  bool
	KeepLearning bool // reconfigure: don't reset an active learning period
}

// Step is one unit of work, shown with a spinner by the UI.
type Step struct {
	Name string
	Run  func() (string, error) // returns an optional detail line
	Soft bool                   // failure is a warning, not fatal
}

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

// CustomID derives a stable ID for a custom bait path.
func CustomID(path string) string {
	h := sha1.Sum([]byte(strings.ToLower(filepath.Clean(path))))
	return "custom-" + hex.EncodeToString(h[:4])
}

// Steps returns the install plan.
func Steps(o Options) []Step {
	var u config.UserInfo
	var cfg *config.Config
	var sec *config.Secrets
	self, _ := os.Executable()
	warnings := []string{}

	return []Step{
		{Name: "Checking your account", Run: func() (string, error) {
			if !winsec.IsElevated() {
				return "", errors.New("installing needs administrator rights")
			}
			var err error
			u, err = CurrentUser()
			if err != nil {
				return "", err
			}
			return "protecting " + u.Name + " (" + u.Profile + ")", nil
		}},
		{Name: "Removing the old PowerShell honeypot (if present)", Soft: true, Run: migrateLegacy},
		{Name: "Pausing the service", Run: func() (string, error) { return "", svcctl.Stop() }},
		{Name: "Installing files to " + paths.InstallDir(), Run: func() (string, error) {
			if err := os.MkdirAll(paths.InstallDir(), 0o755); err != nil {
				return "", err
			}
			for _, dst := range []string{paths.InstalledCLI(), paths.InstalledService()} {
				if paths.Same(self, dst) {
					continue
				}
				if err := copyFile(self, dst); err != nil {
					return "", fmt.Errorf("%s: %w", dst, err)
				}
			}
			return "", nil
		}},
		{Name: "Securing the data folder", Run: func() (string, error) {
			if err := os.MkdirAll(paths.AlertsDir(), 0o755); err != nil {
				return "", err
			}
			// SYSTEM + Administrators: full. Users: read (status, notifier). Nobody else.
			return "", config.SetSDDL(paths.DataDir(), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
		}},
		{Name: "Saving your settings", Run: func() (string, error) {
			old, err := config.LoadConfig()
			if err != nil {
				old = nil
			}
			cfg = config.Default()
			if old != nil {
				*cfg = *old
			}
			cfg.User = u
			if cfg.InstalledAt.IsZero() {
				cfg.InstalledAt = time.Now()
			}
			if o.Preset == "custom" {
				cfg.Preset, cfg.Responses = "custom", o.Responses
			} else if err := cfg.ApplyPreset(o.Preset); err != nil {
				return "", err
			}
			if !(o.KeepLearning && cfg.Learning(time.Now())) {
				cfg.LearningUntil = time.Time{}
				if o.LearningDays > 0 {
					cfg.LearningUntil = time.Now().Add(time.Duration(o.LearningDays) * 24 * time.Hour)
				}
			}
			if o.PhoneMinTier != "" {
				cfg.PhoneMinTier = o.PhoneMinTier
			}
			cfg.CleanRecent = o.CleanRecent
			cfg.Baits = nil
			selected := map[string]bool{}
			for _, id := range o.Baits {
				selected[id] = true
			}
			cfg.User.DecoyBrowser = baits.ChooseHost(selected)
			for _, a := range baits.Plan(cfg.User, ourBaits()) {
				if selected[a.Spec.ID] && a.Available {
					cfg.Baits = append(cfg.Baits, config.BaitConfig{ID: a.Spec.ID})
				}
			}
			for _, p := range o.CustomBaits {
				p = filepath.Clean(p)
				cfg.Baits = append(cfg.Baits, config.BaitConfig{ID: CustomID(p), Path: p})
			}
			sec, _ = config.LoadSecrets()
			if sec == nil {
				sec = &config.Secrets{}
			}
			sec.Phone = o.Phone
			if err := config.SaveSecrets(sec); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s, %d baits", cfg.PresetName(), len(cfg.Baits)), config.SaveConfig(cfg)
		}},
		{Name: "Turning on Windows file auditing", Run: func() (string, error) {
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
			return "", err
		}},
		{Name: "Creating canary tokens", Soft: true, Run: func() (string, error) {
			if o.CanaryEmail == "" {
				return "skipped", nil
			}
			cfg.CanaryEnabled = true
			sec.Canary.Email = o.CanaryEmail
			have := map[string]bool{}
			for _, t := range sec.Canary.Tokens {
				have[t.Kind] = true
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			made := 0
			want := []struct{ kind, memo, bait string }{
				{"aws_keys", "A Better Antivirus: someone used the AWS keys from a decoy ~/.aws/credentials file. Treat that PC as compromised.", "aws"},
				{"web", "A Better Antivirus: someone opened the link from a decoy passwords.txt. Treat that PC as compromised.", "passwords"},
			}
			for _, w := range want {
				if have[w.kind] {
					continue
				}
				t, err := canary.Create(ctx, w.kind, o.CanaryEmail, w.memo, w.bait)
				if err != nil {
					warnings = append(warnings, err.Error())
					continue
				}
				sec.Canary.Tokens = append(sec.Canary.Tokens, t)
				made++
			}
			if err := config.SaveSecrets(sec); err != nil {
				return "", err
			}
			if err := config.SaveConfig(cfg); err != nil {
				return "", err
			}
			if len(warnings) > 0 {
				return "", errors.New(strings.Join(warnings, "; "))
			}
			return fmt.Sprintf("%d token(s); alerts go to %s", made+len(have), o.CanaryEmail), nil
		}},
		{Name: "Planting baits", Run: func() (string, error) { return plantBaits(cfg, sec) }},
		{Name: "Registering the background service", Run: func() (string, error) {
			// Start fresh in the event log: reads made by this installer must not be replayed as alerts.
			config.UpdateState(func(st *config.State) error { st.Bookmark = ""; return nil })
			if err := svcctl.InstallOrUpdate(paths.InstalledService()); err != nil {
				return "", err
			}
			return paths.ServiceDisplayName, svcctl.Start()
		}},
		{Name: "Adding aba to PATH", Soft: true, Run: func() (string, error) { return "", AddToPath(paths.InstallDir()) }},
	}
}

// ourBaits returns IDs of baits currently in state (so our own decoy folders
// don't count as "the real app is installed").
func ourBaits() map[string]bool {
	m := map[string]bool{}
	if st, err := config.LoadState(); err == nil {
		for id, b := range st.Baits {
			if b.Status != "retired" {
				m[id] = true
			}
		}
	}
	return m
}

// SyncBaits makes the planted baits match cfg.Baits (create new, remove deselected).
func SyncBaits(cfg *config.Config) (string, error) {
	sec, err := config.LoadSecrets()
	if err != nil {
		sec = &config.Secrets{}
	}
	return plantBaits(cfg, sec)
}

func plantBaits(cfg *config.Config, sec *config.Secrets) (string, error) {
	created, removed := 0, 0
	var errs []string
	err := config.UpdateState(func(st *config.State) error {
		g := baits.GenFromPersona(st.Persona)
		st.Persona = g.Persona()
		for _, t := range sec.Canary.Tokens {
			g.Canary[t.Kind] = t.Data
		}
		want := map[string]config.BaitConfig{}
		for _, b := range cfg.Baits {
			want[b.ID] = b
		}
		// Remove baits that are no longer selected, and dependents (MetaMask)
		// whose host browser changed. Dependents go first so their files don't
		// keep the host's folders alive.
		host := baits.BrowserUserData(cfg.User, cfg.User.DecoyBrowser)
		drop := func(id string) bool {
			bs := st.Baits[id]
			if _, ok := want[id]; !ok {
				return true
			}
			if spec, ok := baits.ByID(id); ok && len(spec.RequiresAny) > 0 && len(bs.Files) > 0 {
				return !paths.Under(bs.Files[0].Path, host)
			}
			return false
		}
		for _, dependentsFirst := range []bool{true, false} {
			for id, bs := range st.Baits {
				spec, _ := baits.ByID(id)
				if (len(spec.RequiresAny) > 0) != dependentsFirst || !drop(id) {
					continue
				}
				baits.Remove(bs)
				delete(st.Baits, id)
				if _, still := want[id]; !still {
					removed++
				}
			}
		}
		// Create new ones (and re-assert existing ones).
		for _, b := range cfg.Baits {
			spec, ok := baits.SpecFor(b)
			if !ok {
				continue
			}
			if old := st.Baits[b.ID]; old != nil {
				if old.Status == "retired" {
					continue // the real app moved in: never plant fake data over it again
				}
				if probs := baits.Check(old); len(probs) > 0 {
					baits.Repair(old, spec, cfg.User, g, probs)
				}
				continue
			}
			if baits.InstalledMarker(spec, cfg.User) != "" {
				continue // installed since the plan was made
			}
			bs, err := baits.Create(spec, cfg.User, g)
			if err != nil {
				errs = append(errs, err.Error())
				if bs != nil && len(bs.Files) == 0 {
					continue
				}
			}
			st.Baits[b.ID] = bs
			created++
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(errs) > 0 {
		return "", errors.New(strings.Join(errs, "; "))
	}
	return fmt.Sprintf("%d planted, %d removed", created, removed), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// The old binary may be running (e.g. this is `aba install` from PATH);
	// Windows lets us rename a running exe out of the way.
	// Old copies can still be in use (e.g. an alert popup nobody clicked), so
	// each gets a unique name and is deleted now or at the next reboot.
	if olds, _ := filepath.Glob(dst + ".old*"); len(olds) > 0 {
		for _, o := range olds {
			os.Remove(o)
		}
	}
	if _, err := os.Stat(dst); err == nil {
		old := fmt.Sprintf("%s.old-%d", dst, time.Now().UnixNano())
		if err := os.Rename(dst, old); err != nil {
			return err
		}
		scheduleDelete(old)
	}
	return os.Rename(tmp, dst)
}

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
		return "none found", nil
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

// ---- Uninstall ----

// UninstallSteps removes ABA. Alerts and logs are kept unless purge.
func UninstallSteps(purge bool) []Step {
	var canaryLinks []string
	return []Step{
		{Name: "Stopping and removing the service", Run: func() (string, error) { return "", svcctl.Delete() }},
		{Name: "Releasing frozen processes and network blocks", Soft: true, Run: func() (string, error) {
			rep, err := respond.Release("")
			if err != nil {
				return "", err
			}
			netguard.RemoveAll()
			return strings.Join(rep.Lines, "; "), nil
		}},
		{Name: "Removing baits", Run: func() (string, error) {
			n := 0
			if s, err := config.LoadSecrets(); err == nil {
				for _, t := range s.Canary.Tokens {
					canaryLinks = append(canaryLinks, t.ManageURL)
				}
			}
			err := config.UpdateState(func(st *config.State) error {
				for id, bs := range st.Baits {
					baits.Remove(bs)
					delete(st.Baits, id)
					n++
				}
				return nil
			})
			return fmt.Sprintf("%d removed", n), err
		}},
		{Name: "Restoring Windows audit settings", Soft: true, Run: func() (string, error) {
			st, err := config.LoadState()
			if err != nil || st.AuditOriginal == nil {
				return "left as is", nil
			}
			return "", winsec.SetFileSystemAudit(*st.AuditOriginal)
		}},
		{Name: "Removing from PATH", Soft: true, Run: func() (string, error) { return "", RemoveFromPath(paths.InstallDir()) }},
		{Name: "Deleting program files", Soft: true, Run: func() (string, error) {
			self, _ := os.Executable()
			if paths.Under(self, paths.InstallDir()) {
				// Can't delete ourselves while running: let cmd do it after we exit.
				cmd := exec.Command("cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul & rmdir /s /q \""+paths.InstallDir()+"\"")
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS}
				return "finishes after this window closes", cmd.Start()
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
		}},
		{Name: "Cleaning up data", Run: func() (string, error) {
			if purge {
				return "everything deleted", os.RemoveAll(paths.DataDir())
			}
			for _, f := range []string{paths.ConfigFile(), paths.StateFile(), paths.SecretsFile(), paths.TestFile()} {
				os.Remove(f)
			}
			msg := "kept alert history in " + paths.DataDir()
			if len(canaryLinks) > 0 {
				msg += ". Deactivate your canary tokens at: " + strings.Join(canaryLinks, " , ")
			}
			return msg, nil
		}},
	}
}

// Reload asks the running service to re-read its configuration.
func Reload() error { return svcctl.Control(svc.ParamChange) }
