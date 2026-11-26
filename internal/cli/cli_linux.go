package cli

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
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/vulnix0x4/a-better-antivirus/internal/config"
	"github.com/vulnix0x4/a-better-antivirus/internal/install"
	"github.com/vulnix0x4/a-better-antivirus/internal/ui"
)

// requireAdmin returns nil if this process is root. Otherwise, at a terminal,
// it runs the same command again through sudo (which asks for the password
// there), waits for it and returns errRelaunched; without a terminal it says
// how to.
func requireAdmin() error {
	if os.Geteuid() == 0 {
		// What root creates from here on (the program's folder, the link on
		// the PATH) has to be usable by everyone, whatever root's own umask is.
		unix.Umask(0o022)
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	sudo, lerr := exec.LookPath("sudo")
	if lerr != nil || !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("this needs root: run it as `sudo %s`", filepath.Base(os.Args[0])+argsText())
	}
	fmt.Println()
	fmt.Println(" " + ui.Warn.Bold(true).Render("!") + " " + ui.Plain.Render("This needs root.") + ui.Dim.Render(" Asking sudo:"))
	cmd := exec.Command(sudo, append([]string{exe}, os.Args[1:]...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// It said what went wrong itself: don't say it twice.
			os.Exit(ee.ExitCode())
		}
		return fmt.Errorf("could not run sudo: %v", err)
	}
	return errRelaunched
}

func argsText() string {
	s := ""
	for _, a := range os.Args[1:] {
		s += " " + a
	}
	return s
}

// shouldPause: a terminal doesn't vanish with the result.
func shouldPause() bool { return false }

// The fake stealer for `aba test` runs from the temp folder, where real ones
// do, and as the user being protected, the way a real one runs. `aba test`
// itself is root, and the temp folder is everyone's: so the file gets a name
// nobody can guess, is created new (never over something that's there), and
// belongs to root, in a folder where only a file's owner may replace it. A
// program running as the user can neither change it nor swap it.

// testReader is the running fake stealer.
type testReader struct {
	Path string
	PID  uint32
	As   string // how it was started
	cmd  *exec.Cmd
}

// startTestReader writes a copy of this program (self) into the temp folder
// and starts it as `test-reader <target>`, as the protected user.
func startTestReader(self []byte, target string) (*testReader, error) {
	var who config.UserInfo
	if cfg, err := config.LoadConfig(); err == nil {
		who = cfg.User
	} else if u, err := install.CurrentUser(); err == nil {
		who = u
	} else {
		return nil, err
	}
	uid, err := strconv.ParseUint(who.SID, 10, 32)
	if err != nil || uid == 0 {
		return nil, fmt.Errorf("can't tell which account to run the fake stealer as")
	}
	gid := uid
	if u, err := user.LookupId(who.SID); err == nil {
		if g, err := strconv.ParseUint(u.Gid, 10, 32); err == nil {
			gid = g
		}
	} else if fi, err := os.Stat(who.Profile); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			gid = uint64(st.Gid)
		}
	}
	name := make([]byte, 8)
	if _, err := rand.Read(name); err != nil {
		return nil, err
	}
	var errs []string
	// The temp folder first; the others for systems that don't allow running
	// programs from it.
	for _, dir := range []string{os.TempDir(), "/var/tmp", "/dev/shm"} {
		path := filepath.Join(dir, "aba-test-"+hex.EncodeToString(name))
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o755)
		if err != nil {
			errs = append(errs, fmt.Sprintf("create %s: %v", path, err))
			continue
		}
		f := os.NewFile(uintptr(fd), path)
		_, werr := f.Write(self)
		if werr == nil {
			werr = f.Chmod(0o755)
		}
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(path)
			errs = append(errs, werr.Error())
			continue
		}
		cmd := exec.Command(path, "test-reader", target)
		cmd.Dir = "/"
		cmd.Env = []string{"HOME=" + who.Profile, "USER=" + who.Name, "LOGNAME=" + who.Name, "PATH=/usr/local/bin:/usr/bin:/bin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if os.Geteuid() == 0 {
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}
		}
		if err := cmd.Start(); err != nil {
			os.Remove(path)
			errs = append(errs, fmt.Sprintf("start %s: %v", path, err))
			continue
		}
		return &testReader{Path: path, PID: uint32(cmd.Process.Pid), As: "as " + who.Name, cmd: cmd}, nil
	}
	return nil, fmt.Errorf("start the fake stealer: %v", errs)
}

// Close ends the fake stealer (if it's still there) and deletes its file.
func (r *testReader) Close() {
	if r.cmd != nil {
		r.cmd.Process.Kill()
		done := make(chan struct{})
		go func() { r.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		r.cmd = nil
	}
	os.Remove(r.Path)
}

// requireAdminQuietly is requireAdmin: sudo asks in this same terminal.
func requireAdminQuietly(why string) error { return requireAdmin() }
