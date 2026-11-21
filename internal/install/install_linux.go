package install

// What installing takes on Linux beyond the shared plan: finding out who is
// being protected (the person who ran sudo, not root), checking that this
// kernel can watch files, and the `aba` link on the PATH.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/fanwatch"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/procinfo"
)

// CurrentUser resolves the user being protected: whoever ran the installer,
// not root, whom it runs as. In order: ABA_USER (a name, to say it outright),
// the account sudo or pkexec was called from, the account this login session
// belongs to.
func CurrentUser() (config.UserInfo, error) {
	var u *user.User
	if name := os.Getenv("ABA_USER"); name != "" {
		found, err := lookupUser(name)
		if err != nil {
			return config.UserInfo{}, fmt.Errorf("ABA_USER=%s: %w", name, err)
		}
		u = found
	}
	for _, v := range []string{"SUDO_UID", "PKEXEC_UID"} {
		if id := os.Getenv(v); u == nil && id != "" && id != "0" {
			u, _ = lookupUser(id)
		}
	}
	if u == nil {
		if b, err := os.ReadFile("/proc/self/loginuid"); err == nil {
			if id := strings.TrimSpace(string(b)); id != "0" && id != "4294967295" {
				u, _ = lookupUser(id)
			}
		}
	}
	if u == nil && os.Geteuid() != 0 {
		u, _ = user.Current()
	}
	if u == nil || u.Uid == "0" {
		return config.UserInfo{}, errors.New("couldn't tell whose files to protect: run it with sudo from that person's account, or name them with ABA_USER=<name> (protecting root's own account isn't supported yet)")
	}
	home := u.HomeDir
	if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
		return config.UserInfo{}, fmt.Errorf("%s has no home folder (%s)", u.Username, home)
	}
	cfgHome, dataHome := filepath.Join(home, ".config"), filepath.Join(home, ".local", "share")
	dirs := xdgUserDirs(home, cfgHome)
	return config.UserInfo{
		SID: u.Uid, Name: u.Username, Profile: home,
		Desktop: dirs["DESKTOP"], Documents: dirs["DOCUMENTS"], Downloads: dirs["DOWNLOAD"],
		// The nearest things Linux has to AppData: where apps keep their
		// settings, and where they keep their data.
		RoamingAppData: cfgHome, LocalAppData: dataHome,
	}, nil
}

// lookupUser finds an account by name or numeric ID: in /etc/passwd, and
// failing that through the system's own lookup (accounts from a directory
// service aren't in the file).
func lookupUser(nameOrID string) (*user.User, error) {
	if _, err := strconv.Atoi(nameOrID); err == nil {
		if u, err := user.LookupId(nameOrID); err == nil {
			return u, nil
		}
	} else if u, err := user.Lookup(nameOrID); err == nil {
		return u, nil
	}
	for _, getent := range []string{"/usr/bin/getent", "/bin/getent"} {
		out, err := exec.Command(getent, "passwd", nameOrID).Output()
		if err != nil {
			continue
		}
		f := strings.Split(strings.TrimSpace(string(out)), ":") // name:x:uid:gid:gecos:home:shell
		if len(f) >= 6 {
			return &user.User{Username: f[0], Uid: f[2], Gid: f[3], Name: f[4], HomeDir: f[5]}, nil
		}
	}
	return nil, fmt.Errorf("no such account")
}

// xdgUserDirs reads where the user's Desktop, Documents and Downloads are
// (~/.config/user-dirs.dirs), falling back to the usual names. The file is
// the user's own: what it says is only ever used as a place to plant a bait
// with that user's rights.
func xdgUserDirs(home, cfgHome string) map[string]string {
	out := map[string]string{"DESKTOP": filepath.Join(home, "Desktop"), "DOCUMENTS": filepath.Join(home, "Documents"), "DOWNLOAD": filepath.Join(home, "Downloads")}
	f, err := os.Open(filepath.Join(cfgHome, "user-dirs.dirs"))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// XDG_DESKTOP_DIR="$HOME/Desktop"
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		k = strings.TrimSuffix(strings.TrimPrefix(k, "XDG_"), "_DIR")
		if _, known := out[k]; !ok || !known {
			continue
		}
		v = strings.Trim(v, `"`)
		switch {
		case v == "$HOME" || v == "$HOME/":
			continue // "no such folder": the home folder itself stands in
		case strings.HasPrefix(v, "$HOME/"):
			v = filepath.Join(home, v[len("$HOME/"):])
		case !filepath.IsAbs(v):
			continue
		}
		out[k] = filepath.Clean(v)
	}
	return out
}

// cleanupSteps: no earlier generations of ABA on Linux to clear away.
func cleanupSteps() []Step { return nil }

// detectionSteps check what Linux needs to notice a bait being opened and to
// keep a program frozen. Nothing has to be switched on, so there is nothing
// to remember for uninstall; this only says early, and plainly, when a
// kernel can't do it.
func detectionSteps() []Step {
	return []Step{{Name: "Checking that this kernel can watch files", Run: func() (string, error) {
		w, err := fanwatch.New()
		if err != nil {
			return "", fmt.Errorf("ABA can't watch files here: %w", err)
		}
		held := w.Held()
		w.Close()
		go w.Run() // lets go of it
		detail := "fanotify: the kernel stops whoever opens a bait until ABA has looked"
		if !held {
			detail = "fanotify without permission events: readers are frozen a moment after they open a bait, not before"
		}
		if err := procinfo.FreezerStatus(); err != nil {
			detail += "; no cgroup v2 freezer, so a frozen program is only stopped"
		}
		return detail, nil
	}}}
}

// restoreSteps undo what's left in the system on uninstall: the frozen
// control group (whatever is still in it was released a step earlier) and
// ABA's folder under /run.
func restoreSteps() []Step {
	return []Step{{Name: "Removing the frozen group", Soft: true, Run: func() (string, error) {
		err := procinfo.RemoveFreezer()
		os.RemoveAll(paths.RunDir())
		return "", err
	}}}
}

// The command people type is a link in /usr/local/bin, which is on
// everyone's PATH, to the installed program.
const pathLink = "/usr/local/bin/" + paths.CLIExe

func ours(dir string) bool {
	target, err := os.Readlink(pathLink)
	return err == nil && target == filepath.Join(dir, paths.CLIExe)
}

// AddToPath makes `aba` in dir something people can type in a terminal.
func AddToPath(dir string) error {
	if ours(dir) {
		return nil
	}
	if _, err := os.Lstat(pathLink); err == nil {
		return fmt.Errorf("%s already exists and isn't ABA's: run %s directly, or remove it", pathLink, filepath.Join(dir, paths.CLIExe))
	}
	if err := os.MkdirAll(filepath.Dir(pathLink), 0o755); err != nil {
		return err
	}
	return os.Symlink(filepath.Join(dir, paths.CLIExe), pathLink)
}

// RemoveFromPath undoes AddToPath.
func RemoveFromPath(dir string) error {
	if !ours(dir) {
		return nil
	}
	return os.Remove(pathLink)
}

// deleteProgramFiles removes the install folder on uninstall. A running
// program can be deleted on Linux, the one doing the uninstalling included.
func deleteProgramFiles() (string, error) {
	return "", os.RemoveAll(paths.InstallDir())
}

// scheduleDelete deletes p (see deleteProgramFiles: now always works).
func scheduleDelete(p string) { os.Remove(p) }
