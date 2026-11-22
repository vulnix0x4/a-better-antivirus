package svcctl

// The service on macOS is a launchd daemon. It keeps the neutral name the
// Windows service has ("File Access Monitor"), for the same reason: no need
// to tell a stealer listing services what this is.
//
// It runs a program inside an app bundle (see paths_darwin.go) and the daemon
// names that bundle (AssociatedBundleIdentifiers). That's what makes it show
// up as "File Access Monitor" in System Settings' Full Disk Access list, where
// it has to be switched on: the service watches baits through Apple's
// eslogger, which only runs for a program with Full Disk Access.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
	"github.com/vulnix0x4/a-better-antivirus/internal/provenance"
)

const (
	// Label is the launchd job's name.
	Label     = paths.BundleID
	plistFile = "/Library/LaunchDaemons/" + Label + ".plist"
	target    = "system/" + Label
)

// ReadyFile is where the running service writes its PID once it's watching
// the baits (or has given up waiting to: see service_darwin.go). Start waits
// for it.
func ReadyFile() string { return filepath.Join(paths.DataDir(), "ready") }

// WatchingFile exists while the running service is watching the baits (it
// has Full Disk Access and eslogger runs). It holds the service's PID.
func WatchingFile() string { return filepath.Join(paths.DataDir(), "watching") }

// Watching reports whether the running service is watching the baits.
func Watching() bool {
	b, err := os.ReadFile(WatchingFile())
	if err != nil {
		return false
	}
	_, _, pid := job()
	return pid > 0 && strings.TrimSpace(string(b)) == strconv.Itoa(pid)
}

func launchctl(args ...string) (string, error) {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("launchctl %s: %s", strings.Join(args, " "), firstLine(text))
		}
		return text, fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return text, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

var (
	stateRe = regexp.MustCompile(`(?m)^\tstate = (\S+)`)
	pidRe   = regexp.MustCompile(`(?m)^\tpid = (\d+)`)
)

// job reports whether launchd has the daemon loaded, its state ("running",
// "not running"…) and its PID (0: none).
func job() (loaded bool, state string, pid int) {
	out, err := launchctl("print", target)
	if err != nil {
		return false, "", 0
	}
	if m := stateRe.FindStringSubmatch(out); m != nil {
		state = m[1]
	}
	if m := pidRe.FindStringSubmatch(out); m != nil {
		pid, _ = strconv.Atoi(m[1])
	}
	return true, state, pid
}

// Status reports whether the service is installed and running. It works
// without root.
func Status() (State, error) {
	if _, err := os.Stat(plistFile); err != nil {
		return NotInstalled, nil
	}
	loaded, state, pid := job()
	switch {
	case !loaded:
		return Stopped, nil
	case state == "running" && pid > 0:
		return Running, nil
	case state == "spawn scheduled" || state == "spawning":
		return Starting, nil
	}
	return Stopped, nil
}

// infoPlist makes the program folder an app bundle that never shows a window
// or a Dock icon.
func infoPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>` + paths.BundleID + `</string>
	<key>CFBundleName</key>
	<string>` + paths.ServiceDisplayName + `</string>
	<key>CFBundleDisplayName</key>
	<string>` + paths.ServiceDisplayName + `</string>
	<key>CFBundleExecutable</key>
	<string>` + paths.ServiceExe + `</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>LSMinimumSystemVersion</key>
	<string>14.0</string>
	<key>LSBackgroundOnly</key>
	<true/>
	<key>LSUIElement</key>
	<true/>
</dict>
</plist>
`
}

// plistText is the daemon: root, started at boot, restarted if it ever dies.
func plistText(exe string) string {
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + esc(exe) + `</string>
		<string>service</string>
		<string>run</string>
	</array>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>` + paths.BundleID + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>2</integer>
	<key>ExitTimeOut</key>
	<integer>25</integer>
	<key>Umask</key>
	<integer>63</integer>
	<key>ProcessType</key>
	<string>Standard</string>
</dict>
</plist>
`
}

// InstallOrUpdate registers the service to run exe at boot, as root,
// restarting automatically if it ever dies. exe is the bundle's main program
// (paths.InstalledService): this also writes the bundle's description and,
// unless the program carries a real signature already, signs the bundle
// ad hoc so that macOS can tell it apart from anything else.
func InstallOrUpdate(exe string) error {
	contents := filepath.Dir(filepath.Dir(exe))
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(infoPlist()), 0o644); err != nil {
		return err
	}
	if !provenance.Verify(exe).Valid {
		bundle := filepath.Dir(contents)
		if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", paths.BundleID, bundle).CombinedOutput(); err != nil {
			return fmt.Errorf("sign %s: %v (%s)", bundle, err, strings.TrimSpace(string(out)))
		}
	}
	if err := os.WriteFile(plistFile, []byte(plistText(exe)), 0o644); err != nil {
		return err
	}
	os.Chown(plistFile, 0, 0)
	return os.Chmod(plistFile, 0o644)
}

// Start starts the service and waits until it's protecting: it writes
// ReadyFile once the baits are watched (or once it has waited long enough
// for Full Disk Access).
func Start() error {
	if st, _ := Status(); st == Running {
		return nil
	}
	if loaded, _, _ := job(); loaded {
		if _, err := launchctl("kickstart", target); err != nil {
			return err
		}
	} else if _, err := launchctl("bootstrap", "system", plistFile); err != nil {
		return fmt.Errorf("%w (see %s)", err, paths.LogFile())
	}
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		_, state, pid := job()
		if pid > 0 {
			if b, err := os.ReadFile(ReadyFile()); err == nil && strings.TrimSpace(string(b)) == strconv.Itoa(pid) {
				return nil
			}
		} else if state != "" && state != "spawn scheduled" && state != "spawning" && state != "running" && time.Until(deadline) < 30*time.Second {
			return fmt.Errorf("the service didn't start (launchd says %q; see %s)", state, paths.LogFile())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st, _ := Status(); st == Running {
		return nil
	}
	return fmt.Errorf("the service didn't start in time (see %s)", paths.LogFile())
}

// Stop stops the service and waits until it's gone (no service: nothing to
// do). launchd would restart a daemon that's only killed, so it's unloaded;
// Start loads it again.
func Stop() error {
	loaded, _, pid := job()
	if !loaded {
		return nil
	}
	if _, err := launchctl("bootout", target); err != nil {
		if again, _, _ := job(); again {
			return err
		}
	}
	for i := 0; i < 150 && pid > 0; i++ {
		if unix.Kill(pid, 0) != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

// Delete stops the service and unregisters it (no service: nothing to do).
func Delete() error {
	if err := Stop(); err != nil {
		return err
	}
	if err := os.Remove(plistFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// How each Signal travels to the service: as a Unix signal to its process,
// which only root can send.
var signals = map[Signal]unix.Signal{Reload: unix.SIGHUP, CheckNow: unix.SIGUSR1, Released: unix.SIGUSR2}

// Send tells the running service something (see Signal).
func Send(sig Signal) error {
	s, ok := signals[sig]
	if !ok {
		return fmt.Errorf("unknown signal %d", sig)
	}
	_, _, pid := job()
	if pid <= 1 {
		return errors.New("the service isn't running")
	}
	return unix.Kill(pid, s)
}

// ConsoleUser is the person logged in at the screen: the owner of
// /dev/console.
func ConsoleUser() (uint32, bool) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// fdaPane is System Settings > Privacy & Security > Full Disk Access.
const fdaPane = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles"

// OpenFullDiskAccess opens the Full Disk Access settings for the person at
// the screen (not as root: System Settings belongs to them).
func OpenFullDiskAccess() error {
	uid, ok := ConsoleUser()
	if !ok || uid == 0 {
		return errors.New("nobody is logged in at the screen")
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return err
	}
	return exec.Command("/bin/launchctl", "asuser", u.Uid, "/usr/bin/sudo", "-u", u.Username, "/usr/bin/open", fdaPane).Run()
}
