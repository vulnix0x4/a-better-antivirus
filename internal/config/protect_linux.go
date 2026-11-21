package config

// How Linux keeps ABA's data to itself: everything belongs to root and only
// root may read it, and a lock file serialises the service and the CLI.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// protect would encrypt the secrets with a key the machine keeps. Linux has
// no such store that works everywhere (a TPM-bound one, systemd-creds, needs
// a recent systemd and a TPM), so for now the secrets are protected by who
// may read the file: root alone (restrictSecrets). Copying the file off the
// machine takes root, and root can read any key ABA could keep here anyway.
func protect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		b = []byte("{}")
	}
	return b, nil
}

func unprotect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return []byte("{}"), nil
	}
	return b, nil
}

// restrictSecrets leaves the secrets file to root only.
func restrictSecrets(path string) error {
	if os.Geteuid() == 0 {
		if err := os.Lchown(path, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(path, 0o600)
}

// lockDir makes dir (and everything already in it) root's alone, except for
// its public subfolder, which anyone may read.
//
// The folder itself can be passed through (but not listed) by everyone,
// because the public folder is inside it. Every file in it is closed, so
// knowing a file's name gets a program running as you nothing.
func lockDir(dir, public string) error {
	for _, d := range []string{dir, public} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	own := func(p string) {
		if os.Geteuid() == 0 {
			os.Lchown(p, 0, 0)
		}
	}
	own(dir)
	if err := os.Chmod(dir, 0o711); err != nil {
		return err
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil // nothing of ABA's is a link; never follow one
		}
		own(p)
		inPublic := p == public || paths.Under(p, public)
		switch {
		case d.IsDir() && inPublic:
			return os.Chmod(p, 0o755)
		case d.IsDir():
			return os.Chmod(p, 0o700)
		case inPublic:
			return os.Chmod(p, 0o644)
		}
		return os.Chmod(p, 0o600)
	})
	return err
}

// readableByAll opens the published status file to everyone. Files are
// written under a private name first, so they start out closed.
func readableByAll(path string) error { return os.Chmod(path, 0o644) }

// inProcess serialises goroutines within one process; the file lock below
// does the same between the service and the CLI.
var inProcess sync.Mutex

func lockState() (func(), error) {
	inProcess.Lock()
	fail := func(err error) (func(), error) {
		inProcess.Unlock()
		return nil, err
	}
	if err := os.MkdirAll(paths.DataDir(), 0o711); err != nil {
		return fail(fmt.Errorf("state lock: %w", err))
	}
	f, err := os.OpenFile(filepath.Join(paths.DataDir(), ".state.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fail(fmt.Errorf("state lock: %w", err))
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return fail(fmt.Errorf("state lock: %w", err))
		}
		if time.Now().After(deadline) {
			f.Close()
			return fail(fmt.Errorf("state lock: timed out"))
		}
		time.Sleep(15 * time.Millisecond)
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		inProcess.Unlock()
	}, nil
}
