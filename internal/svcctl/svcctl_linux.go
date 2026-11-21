package svcctl

// The service on Linux is a systemd unit. It keeps the neutral name the
// Windows service has ("File Access Monitor"), for the same reason: no need
// to tell a stealer listing services what this is.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

const (
	// Unit is the systemd unit's name.
	Unit     = "file-access-monitor.service"
	unitFile = "/etc/systemd/system/" + Unit
)

var errNoSystemd = errors.New("this system isn't run by systemd, which ABA's service needs for now")

func systemctl(args ...string) (string, error) {
	bin := ""
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(p); err == nil {
			bin = p
			break
		}
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil || bin == "" {
		return "", errNoSystemd
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), firstLine(text))
		}
		return text, fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return text, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// Status reports whether the service is installed and running. It works
// without root.
func Status() (State, error) {
	if _, err := os.Stat(unitFile); err != nil {
		return NotInstalled, nil
	}
	// is-active exits non-zero for anything but "active": the word is what counts.
	out, err := systemctl("is-active", Unit)
	if errors.Is(err, errNoSystemd) {
		return Unknown, err
	}
	switch firstLine(out) {
	case "active", "reloading":
		return Running, nil
	case "activating":
		return Starting, nil
	case "deactivating":
		return Stopping, nil
	case "inactive", "failed":
		return Stopped, nil
	}
	return Unknown, nil
}

// unitText is the unit: root, started at boot, restarted if it ever dies.
//
// It is deliberately not sandboxed with systemd's hardening options: the
// service has to see the real file system (bait files in home folders), every
// process (/proc) and the whole control-group tree, and those options work by
// hiding exactly that.
func unitText(exe string) string {
	return `[Unit]
Description=` + paths.ServiceDisplayName + `
After=local-fs.target

[Service]
Type=notify
NotifyAccess=main
ExecStart="` + exe + `" service run
Restart=always
RestartSec=2
TimeoutStartSec=60
TimeoutStopSec=25
UMask=0077
OOMScoreAdjust=-800

[Install]
WantedBy=multi-user.target
`
}

// InstallOrUpdate registers the service to run exe at boot, as root,
// restarting automatically if it ever dies.
func InstallOrUpdate(exe string) error {
	if _, err := systemctl("--version"); err != nil {
		return err
	}
	if err := os.WriteFile(unitFile, []byte(unitText(exe)), 0o644); err != nil {
		return err
	}
	os.Chmod(unitFile, 0o644)
	if _, err := systemctl("daemon-reload"); err != nil {
		return err
	}
	_, err := systemctl("enable", Unit)
	return err
}

// Start starts the service and waits until it's protecting (the unit only
// reports "started" once baits are watched).
func Start() error {
	if st, _ := Status(); st == Running {
		return nil
	}
	if _, err := systemctl("start", Unit); err != nil {
		return fmt.Errorf("%w (see %s, and `journalctl -u %s`)", err, paths.LogFile(), Unit)
	}
	return nil
}

// Stop stops the service and waits until it's gone (no service: nothing to do).
func Stop() error {
	if st, _ := Status(); st == NotInstalled || st == Stopped {
		return nil
	}
	_, err := systemctl("stop", Unit)
	return err
}

// Delete stops the service and unregisters it (no service: nothing to do).
func Delete() error {
	if _, err := os.Stat(unitFile); err != nil {
		return nil
	}
	systemctl("stop", Unit)
	systemctl("disable", Unit)
	if err := os.Remove(unitFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	systemctl("daemon-reload")
	systemctl("reset-failed", Unit)
	return nil
}

// How each Signal travels to the service: as a Unix signal to its main
// process, which only root can send.
var signals = map[Signal]unix.Signal{Reload: unix.SIGHUP, CheckNow: unix.SIGUSR1, Released: unix.SIGUSR2}

// Send tells the running service something (see Signal).
func Send(sig Signal) error {
	s, ok := signals[sig]
	if !ok {
		return fmt.Errorf("unknown signal %d", sig)
	}
	out, err := systemctl("show", "-p", "MainPID", "--value", Unit)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(firstLine(out))
	if err != nil || pid <= 1 {
		return errors.New("the service isn't running")
	}
	return unix.Kill(pid, s)
}
