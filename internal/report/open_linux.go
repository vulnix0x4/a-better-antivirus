package report

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

// Where is how to get back to the reports, said at the bottom of the page
// and in the popup.
func Where() string { return "in a terminal, run sudo aba reports" }

// Open opens url in the default browser (xdg-open), as the person at the
// screen. Run as root (`sudo aba report`), it opens it as the person who
// ran sudo or pkexec, through their own systemd (which knows their
// desktop), never as root.
func Open(url string) error {
	if os.Geteuid() != 0 {
		return openAsMe(url)
	}
	uid := os.Getenv("SUDO_UID")
	if uid == "" {
		uid = os.Getenv("PKEXEC_UID")
	}
	if uid == "" || uid == "0" {
		return errNobody
	}
	u, err := user.LookupId(uid)
	if err != nil {
		return err
	}
	return exec.Command("systemd-run", "--user", "--machine="+u.Username+"@", "--quiet", "--collect", "--", "xdg-open", url).Run()
}

// openAsMe: the popup runs with only the session bus in its environment
// (the service started it), so the address of the screen (DISPLAY,
// WAYLAND_DISPLAY) comes from the person's own systemd, which the desktop
// told when it started.
func openAsMe(url string) error {
	cmd := exec.Command("xdg-open", url)
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		env := os.Environ()
		if out, err := exec.Command("systemctl", "--user", "show-environment").Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				for _, k := range []string{"DISPLAY=", "WAYLAND_DISPLAY=", "XAUTHORITY=", "XDG_CURRENT_DESKTOP=", "XDG_SESSION_TYPE="} {
					if strings.HasPrefix(l, k) {
						env = append(env, l)
					}
				}
			}
		}
		cmd.Env = env
	}
	if err := cmd.Run(); err != nil {
		return errors.New("couldn't open the web browser (xdg-open): " + err.Error())
	}
	return nil
}
