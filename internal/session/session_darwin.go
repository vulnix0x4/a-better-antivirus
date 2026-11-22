package session

// On macOS the desktop belongs to the person logged in at the screen (the
// owner of /dev/console). A program the service starts for them has to run
// in their login session, or it can't put anything on the screen
// (launchctl asuser), and as them, never with the service's rights (sudo -u).

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// LaunchInActiveSessions runs exe with args as the person at the screen. It
// returns the number of sessions it launched into (0 or 1).
func LaunchInActiveSessions(exe string, args ...string) (int, error) {
	return LaunchWithInput(exe, nil, args...)
}

// LaunchWithInput is LaunchInActiveSessions with input on the program's
// standard input. That's how the service hands an alert to the popup: the
// alert files themselves are for administrators only, and a command line can
// be read by anything running as the same user.
func LaunchWithInput(exe string, input []byte, args ...string) (int, error) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return 0, nil // the login window: nobody is logged in at the screen
	}
	if os.Geteuid() != 0 {
		return 0, errors.New("only the service (root) launches into someone's session")
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	cmd := exec.Command("/bin/launchctl", append([]string{"asuser", uid, "/usr/bin/sudo", "-u", "#" + uid, "-H", "--", exe}, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	go cmd.Wait()
	return 1, nil
}
