package report

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// Where is how to get back to the reports, said at the bottom of the page
// and in the popup.
const Where = "in Terminal, run sudo aba reports"

// Open opens url in the default browser, as the person at the screen. Run
// as root (`sudo aba report`), it opens it in their login session and as
// them, never as root.
func Open(url string) error {
	if os.Geteuid() != 0 {
		return exec.Command("/usr/bin/open", url).Run()
	}
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return errNobody
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	return exec.Command("/bin/launchctl", "asuser", uid, "/usr/bin/sudo", "-u", "#"+uid, "-H", "--", "/usr/bin/open", url).Run()
}
