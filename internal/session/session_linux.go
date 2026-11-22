package session

// On Linux the service runs as root, outside anyone's desktop. A desktop
// notification is a message on the user's own session bus (D-Bus), which
// only that user may connect to. So the popup is started as each person who
// has a session bus (/run/user/<uid>/bus), and it talks to their desktop
// itself (see notify).
//
// It runs as a unit of its own, started by systemd as that user: not as a
// child of the service. A child would live in the service's control group,
// which is the one group isolation lets through (see netguard), and a
// program of the user's has no business being there; and it would be ended
// whenever the service restarts. The alert goes in on its standard input,
// from a file only root can read, which systemd opens for it: never on a
// command line, which anything on the machine can read.
//
// A server with nobody at a desktop has session buses only for people logged
// in over SSH, with no notification service on them: the popup sees that and
// ends without showing anything. Alerts there go to the phone, the log, and
// the frozen program's own terminal.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// LaunchInActiveSessions runs exe with args as each logged-in user (never
// with the service's own rights). It returns the number of sessions it
// launched into.
func LaunchInActiveSessions(exe string, args ...string) (int, error) {
	return LaunchWithInput(exe, nil, args...)
}

// LaunchWithInput is LaunchInActiveSessions with input on the program's
// standard input. That's how the service hands an alert to the popup: the
// alert files themselves are for administrators only, and a command line can
// be read by anything running as the same user.
func LaunchWithInput(exe string, input []byte, args ...string) (int, error) {
	n := 0
	var first error
	for _, uid := range People() {
		if err := launch(uid, exe, input, args); err != nil {
			if first == nil {
				first = fmt.Errorf("user %d: %w", uid, err)
			}
			continue
		}
		n++
	}
	return n, first
}

// People lists the accounts people log in with that have a session bus right
// now: the ones a notification could reach.
func People() []uint32 {
	ents, err := os.ReadDir("/run/user")
	if err != nil {
		return nil
	}
	min := uidMin()
	var out []uint32
	for _, e := range ents {
		uid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil || uint32(uid) < min || uid == 65534 {
			continue
		}
		var st unix.Stat_t
		bus := filepath.Join("/run/user", e.Name(), "bus")
		// The bus must be theirs: anything else at that path isn't their desktop.
		if unix.Lstat(bus, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(uid) {
			continue
		}
		out = append(out, uint32(uid))
	}
	return out
}

func uidMin() uint32 {
	b, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return 1000
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "UID_MIN" {
			if v, err := strconv.ParseUint(f[1], 10, 32); err == nil && v > 0 {
				return uint32(v)
			}
		}
	}
	return 1000
}

func systemdRun() string {
	for _, p := range []string{"/usr/bin/systemd-run", "/bin/systemd-run"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func launch(uid uint32, exe string, input []byte, args []string) error {
	run := systemdRun()
	if run == "" {
		return errors.New("systemd-run isn't here")
	}
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return err
	}
	rt := filepath.Join("/run/user", strconv.Itoa(int(uid)))
	cmd := []string{run, "--quiet", "--collect", "--no-ask-password",
		"--uid=" + u.Uid, "--gid=" + u.Gid,
		"--setenv=XDG_RUNTIME_DIR=" + rt,
		"--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=" + filepath.Join(rt, "bus"),
		"--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"--working-directory=" + u.HomeDir,
		// Started means running the program (so its input is open by then).
		"-p", "Type=exec", "-p", "StandardOutput=null", "-p", "StandardError=journal",
	}
	if lang := os.Getenv("LANG"); lang != "" {
		cmd = append(cmd, "--setenv=LANG="+lang)
	}
	var in string
	if input != nil {
		in, err = inputFile(input)
		if err != nil {
			return err
		}
		defer os.Remove(in)
		cmd = append(cmd, "-p", "StandardInput=file:"+in)
	}
	cmd = append(cmd, "--", exe)
	cmd = append(cmd, args...)
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// inputFile holds input until systemd has opened it for the program. Only
// root can read it.
func inputFile(input []byte) (string, error) {
	dir := filepath.Join(paths.RunDir(), "popup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var r [8]byte
	rand.Read(r[:])
	p := filepath.Join(dir, hex.EncodeToString(r[:]))
	if err := os.WriteFile(p, input, 0o600); err != nil {
		return "", err
	}
	return p, nil
}
