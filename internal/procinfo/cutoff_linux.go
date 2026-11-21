package procinfo

// Cutting a program off the network on Linux: the control-group half.
//
// The firewall can't tell programs apart by their file, but it can by the
// control group a connection was made in. So a program that is cut off is
// moved into a group of its own at the top of the tree,
// file-access-monitor.blocked, and package netguard drops everything sent or
// received through a connection made inside it. Like the frozen group, it
// belongs to root and sits at the top of the tree, so nothing running as you
// can take a process out of it; whatever the process starts is born in it.
//
// Where each process came from is noted under /run, as for the freezer, so
// that it goes back there when it's let back on the network.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vulnix0x4/a-better-antivirus/internal/paths"
)

// cutGroup is the cut-off group's name, at the top of the tree.
const cutGroup = "file-access-monitor.blocked"

func cutDir() (string, error) {
	root, err := cgroupRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, cutGroup)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("make the cut-off group: %w", err)
	}
	return dir, nil
}

// CutOffGroup makes the cut-off group if need be, and returns its place in
// the tree ("/file-access-monitor.blocked").
func CutOffGroup() (string, error) {
	if _, err := cutDir(); err != nil {
		return "", err
	}
	return "/" + cutGroup, nil
}

// CgroupID returns the kernel's number for the control group at rel
// ("/system.slice/x.service"): what the firewall compares a connection's
// group with. A group made again under the same name gets a new number.
func CgroupID(rel string) (uint64, error) {
	root, err := cgroupRoot()
	if err != nil {
		return 0, err
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(root, rel), &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return 0, fmt.Errorf("%s isn't a control group", rel)
	}
	return st.Ino, nil
}

// Cgroup returns the v2 control group a process is in ("/user.slice/…").
func Cgroup(pid uint32) string { return cgroupOf(pid) }

// CutOff reports whether pid is in the cut-off group right now.
func CutOff(pid uint32) bool { return cgroupOf(pid) == "/"+cutGroup }

func cutOriginDir() string { return filepath.Join(paths.RunDir(), "blocked") }

// Disconnect moves pid into the cut-off group. A frozen process stays where
// it is (it can't use the network anyway): it goes in once it's let go, if
// its program is still cut off then.
func Disconnect(pid uint32) error {
	if systemPID(pid) || pid == uint32(os.Getpid()) {
		return fmt.Errorf("refusing to cut off pid %d", pid)
	}
	cur := cgroupOf(pid)
	if cur == "/"+cutGroup || cur == "/"+holdGroup {
		return nil
	}
	if cur == "" {
		return fmt.Errorf("pid %d: no control group (gone?)", pid)
	}
	ct, err := CreateTime(pid)
	if err != nil {
		return err
	}
	dir, err := cutDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cutOriginDir(), 0o700); err != nil {
		return err
	}
	rec := filepath.Join(cutOriginDir(), HoldName(pid, ct))
	if err := os.WriteFile(rec, []byte(cur), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(int(pid))), 0o644); err != nil {
		os.Remove(rec)
		return fmt.Errorf("cut off pid %d: %w", pid, err)
	}
	return nil
}

// Disconnected lists the processes in the cut-off group.
func Disconnected() []uint32 {
	root, err := cgroupRoot()
	if err != nil {
		return nil
	}
	var out []uint32
	for _, line := range readLines(filepath.Join(root, cutGroup, "cgroup.procs")) {
		if pid, err := strconv.ParseUint(strings.TrimSpace(line), 10, 32); err == nil {
			out = append(out, uint32(pid))
		}
	}
	return out
}

// cutOrigin is where pid was before it was cut off. A process started by a
// cut-off one was born in the group: it goes where its parent came from.
func cutOrigin(pid uint32) string {
	for p, hops := pid, 0; p > 1 && hops < 32; p, hops = ParentPID(p), hops+1 {
		ct, err := CreateTime(p)
		if err != nil {
			break
		}
		if b, err := os.ReadFile(filepath.Join(cutOriginDir(), HoldName(p, ct))); err == nil {
			return string(b)
		}
	}
	return ""
}

// Reconnect takes pid out of the cut-off group, back where it came from.
func Reconnect(pid uint32) error {
	ct, _ := CreateTime(pid)
	origin := cutOrigin(pid)
	defer os.Remove(filepath.Join(cutOriginDir(), HoldName(pid, ct)))
	if !CutOff(pid) {
		return nil
	}
	if err := moveBack(pid, origin); err != nil {
		return fmt.Errorf("reconnect pid %d: %w", pid, err)
	}
	return nil
}

// RemoveCutOff takes the cut-off group away (uninstall): whatever is still
// in it goes back where it came from first.
func RemoveCutOff() error {
	root, err := cgroupRoot()
	if err != nil {
		return nil
	}
	dir := filepath.Join(root, cutGroup)
	if _, err := os.Stat(dir); err != nil {
		os.RemoveAll(cutOriginDir())
		return nil
	}
	for _, pid := range Disconnected() {
		Reconnect(pid)
	}
	os.RemoveAll(cutOriginDir())
	for try := 0; try < 20; try++ {
		if err = os.Remove(dir); err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}
