package install

// What installing takes on macOS beyond the shared plan: finding out who is
// being protected (the person who ran sudo, not root), checking this Mac can
// run Apple's eslogger, Full Disk Access for the service, and the `aba` link
// on the PATH.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/netguard"
	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/svcctl"
)

// CurrentUser resolves the user being protected: whoever ran the installer,
// not root, whom it runs as. In order: ABA_USER (a name, to say it outright),
// the account sudo was called from, the person logged in at the screen.
func CurrentUser() (config.UserInfo, error) {
	var u *user.User
	if name := os.Getenv("ABA_USER"); name != "" {
		found, err := lookupUser(name)
		if err != nil {
			return config.UserInfo{}, fmt.Errorf("ABA_USER=%s: %w", name, err)
		}
		u = found
	}
	if id := os.Getenv("SUDO_UID"); u == nil && id != "" && id != "0" {
		u, _ = lookupUser(id)
	}
	if u == nil {
		if uid, ok := consoleUser(); ok && uid != 0 {
			u, _ = lookupUser(strconv.FormatUint(uint64(uid), 10))
		}
	}
	if u == nil && os.Geteuid() != 0 {
		u, _ = user.Current()
	}
	if u == nil || u.Uid == "0" {
		return config.UserInfo{}, errors.New("couldn't tell whose files to protect: run it with sudo from that person's account, or name them with ABA_USER=<name>")
	}
	home := u.HomeDir
	if fi, err := os.Stat(home); err != nil || !fi.IsDir() {
		return config.UserInfo{}, fmt.Errorf("%s has no home folder (%s)", u.Username, home)
	}
	// Where Mac apps keep their data: the nearest thing to AppData.
	support := filepath.Join(home, "Library", "Application Support")
	return config.UserInfo{
		SID: u.Uid, Name: u.Username, Profile: home,
		Desktop: filepath.Join(home, "Desktop"), Documents: filepath.Join(home, "Documents"), Downloads: filepath.Join(home, "Downloads"),
		RoamingAppData: support, LocalAppData: support,
	}, nil
}

func lookupUser(nameOrID string) (*user.User, error) {
	if _, err := strconv.Atoi(nameOrID); err == nil {
		return user.LookupId(nameOrID)
	}
	return user.Lookup(nameOrID)
}

func consoleUser() (uint32, bool) { return svcctl.ConsoleUser() }

// cleanupSteps: no earlier generations of ABA on macOS to clear away.
func cleanupSteps() []Step { return nil }

// detectionSteps check that this Mac can run what ABA watches baits with.
// Nothing has to be switched on in the system (Full Disk Access is asked for
// once the service runs: permissionSteps).
func detectionSteps() []Step {
	return []Step{{Name: "Checking that this Mac can watch files", Run: func() (string, error) {
		out, _ := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
		v := strings.TrimSpace(string(out))
		major, _ := strconv.Atoi(strings.Split(v, ".")[0])
		if major != 0 && major < 14 {
			return "", fmt.Errorf("ABA needs macOS 14 or newer (this Mac has %s)", v)
		}
		if _, err := os.Stat("/usr/bin/eslogger"); err != nil {
			return "", errors.New("this Mac has no /usr/bin/eslogger, which ABA watches files with")
		}
		return "macOS " + v + ", Apple's Endpoint Security (eslogger)", nil
	}}}
}

// restoreSteps undo what's left in the system on uninstall: the network
// rules (whatever was isolated was released a step earlier) and the Full
// Disk Access entry.
func restoreSteps() []Step {
	return []Step{{Name: "Removing network rules and Full Disk Access", Soft: true, Run: func() (string, error) {
		err := netguard.RemoveAll()
		exec.Command("/usr/bin/tccutil", "reset", "SystemPolicyAllFiles", paths.BundleID).Run()
		return "", err
	}}}
}

// permissionSteps ask for Full Disk Access, which macOS only lets the person
// at the screen give: without it the service can't watch the baits. The
// service has already asked for it once, which is what put "File Access
// Monitor" in the list; switching it on takes effect at once.
func permissionSteps() []Step {
	return []Step{{Name: "Full Disk Access: switch on \"" + paths.ServiceDisplayName + "\" in the window that opens", Run: func() (string, error) {
		if svcctl.Watching() {
			return "already on", nil
		}
		opened := svcctl.OpenFullDiskAccess() == nil
		deadline := time.Now().Add(5 * time.Minute)
		if !opened {
			deadline = time.Now().Add(20 * time.Second)
		}
		for time.Now().Before(deadline) {
			if svcctl.Watching() {
				return "on: the service is watching the baits", nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		svcctl.Send(svcctl.CheckNow)
		return "", fmt.Errorf("not switched on yet. Until it is, ABA can't see the baits being opened: open System Settings > Privacy & Security > Full Disk Access and switch on \"%s\" (`aba doctor` checks)", paths.ServiceDisplayName)
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

// deleteProgramFiles removes the app on uninstall (a running program can be
// deleted on macOS, the one doing the uninstalling included), and ABA's
// folder if nothing else is left in it.
func deleteProgramFiles() (string, error) {
	if err := os.RemoveAll(paths.AppBundle()); err != nil {
		return "", err
	}
	os.Remove(paths.SupportDir()) // only if empty: the data folder may be kept
	return "", nil
}

// scheduleDelete deletes p (see deleteProgramFiles: now always works).
func scheduleDelete(p string) { os.Remove(p) }

// appSteps: the app bundle is where macOS looks for ABA (Full Disk Access
// lists it by name); there's no list of installed programs to add it to.
func appSteps(version string) []Step { return nil }
func removeAppSteps() []Step         { return nil }

// RefreshApp: nothing lists ABA's version on macOS.
func RefreshApp(version string) error { return nil }
