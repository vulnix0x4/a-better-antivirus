package procinfo

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A "hold" keeps a frozen process frozen.
//
// NtSuspendProcess alone isn't enough: any other program running as the same
// user can call NtResumeProcess on it, so a stealer with a second process (a
// watchdog, its parent, code it injected elsewhere) un-freezes itself in one
// call. A hold puts the process in a job object and freezes the job. Only
// whoever has the job's handle can thaw it, and that's the service alone: the
// job has no name, so there's nothing for anyone else to open.
//
// The job is also set to kill what's in it when its handle closes, so if the
// service dies while something is held, the suspect dies with it instead of
// staying frozen forever with nobody able to thaw it. Releasing a hold
// clears that first.
//
// The elevated CLI can't reach a hold either (it was tried: Windows refuses
// an administrator's program a job made by a service in another session). It
// doesn't need to: `aba resume` takes the process off the record and tells
// the service, which lets go of every hold that's no longer on record.

var (
	procNtSetInformationJobObject = ntdll.NewProc("NtSetInformationJobObject")

	holdMu sync.Mutex
	holds  = map[string]windows.Handle{} // HoldName -> job handle
	heldAt = map[string]time.Time{}
)

const jobObjectFreezeInformation = 18

// jobFreeze is JOBOBJECT_FREEZE_INFORMATION.
type jobFreeze struct {
	Flags      uint32 // bit 0: this call changes the frozen state
	Freeze     uint8
	Swap       uint8
	_          [2]uint8
	HighFilter uint32
	LowFilter  uint32
}

// HoldName identifies a process for holds: its PID and creation time.
func HoldName(pid uint32, createTime int64) string {
	return fmt.Sprintf("%d-%x", pid, uint64(createTime))
}

func setFrozen(job windows.Handle, on bool) error {
	f := jobFreeze{Flags: 1}
	if on {
		f.Freeze = 1
	}
	if r, _, _ := procNtSetInformationJobObject.Call(uintptr(job), jobObjectFreezeInformation, uintptr(unsafe.Pointer(&f)), unsafe.Sizeof(f)); r != 0 {
		return fmt.Errorf("freeze job: NTSTATUS 0x%08x", uint32(r))
	}
	return nil
}

func setKillOnClose(job windows.Handle, on bool) error {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if on {
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	_, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	return err
}

// Hold locks pid frozen (see above). The process should already be suspended;
// the hold is what keeps it that way. It fails for a process Windows won't
// let into another job; the plain suspension then still stands.
func Hold(pid uint32, createTime int64) error {
	name := HoldName(pid, createTime)
	holdMu.Lock()
	defer holdMu.Unlock()
	if _, ok := holds[name]; ok {
		return nil
	}
	job, err := windows.CreateJobObject(nil, nil)
	if job == 0 {
		return fmt.Errorf("create hold: %w", err)
	}
	ph, err := open(pid, windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE)
	if err != nil {
		windows.CloseHandle(job)
		return err
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(job, ph); err != nil {
		windows.CloseHandle(job)
		return fmt.Errorf("put pid %d in a hold: %w", pid, err)
	}
	if err := setFrozen(job, true); err != nil {
		windows.CloseHandle(job) // nothing was set to die with it yet
		return err
	}
	setKillOnClose(job, true)
	holds[name], heldAt[name] = job, time.Now()
	return nil
}

// release lets go of one hold properly: no kill on close, thawed, closed.
// (Order matters: never close a job that still kills on close.)
func release(job windows.Handle) {
	setKillOnClose(job, false)
	setFrozen(job, false)
	windows.CloseHandle(job)
}

// Unhold releases this process's hold on pid, if it has one. The process
// stays suspended if it was (Resume lifts that).
func Unhold(pid uint32, createTime int64) {
	name := HoldName(pid, createTime)
	holdMu.Lock()
	job, ok := holds[name]
	delete(holds, name)
	delete(heldAt, name)
	holdMu.Unlock()
	if ok {
		release(job)
	}
}

// Held reports how many processes this process holds.
func Held() int {
	holdMu.Lock()
	defer holdMu.Unlock()
	return len(holds)
}

// DropHolds lets go of the holds made before madeBefore that keep() no
// longer wants (released by the CLI, killed, exited). Never kills anything.
//
// madeBefore is for callers that decide from a snapshot of the record: a
// process is put on record before it's held, so a hold older than the
// snapshot that isn't in it has been taken off, while a newer one may simply
// not be in the snapshot yet.
func DropHolds(madeBefore time.Time, keep func(name string) bool) {
	holdMu.Lock()
	var drop []windows.Handle
	for name, job := range holds {
		if heldAt[name].Before(madeBefore) && !keep(name) {
			drop = append(drop, job)
			delete(holds, name)
			delete(heldAt, name)
		}
	}
	holdMu.Unlock()
	for _, job := range drop {
		release(job)
	}
}

// UserSID returns the account (SID) a process runs as.
func UserSID(pid uint32) (string, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// SuspendTreeExcept freezes pid and its descendants, leaving out the
// processes in skip (already frozen: suspensions stack, so freezing one twice
// would need two unfreezes) and any that ok (if given) turns down. Returns
// the PIDs it froze.
func SuspendTreeExcept(pid uint32, skip map[uint32]bool, ok func(pid uint32) bool) []uint32 {
	var frozen []uint32
	done := map[uint32]bool{}
	for pass := 0; pass < 2; pass++ {
		snap, err := Snapshot()
		if err != nil {
			return frozen
		}
		for _, p := range Tree(snap, pid) {
			if done[p] || skip[p] || p == 0 || p == 4 || p == windows.GetCurrentProcessId() {
				continue
			}
			done[p] = true
			if ok != nil && !ok(p) {
				continue
			}
			if Suspend(p) == nil {
				frozen = append(frozen, p)
			}
		}
	}
	return frozen
}

// Ancestor is one process up the chain from a reader.
type Ancestor struct {
	PID        uint32
	Image      string
	CreateTime int64
}

// Ancestors walks up from pid: its parent, grandparent… (at most depth),
// stopping where the chain can't be trusted (the parent exited and its PID
// was reused).
func Ancestors(pid uint32, depth int) []Ancestor {
	snap, err := Snapshot()
	if err != nil {
		return nil
	}
	var out []Ancestor
	cur, ok := snap[pid]
	for i := 0; ok && i < depth; i++ {
		pp, found := snap[cur.PPID]
		if !found || cur.PPID == 0 || cur.PPID == cur.PID {
			break
		}
		if pp.CreateTime != 0 && cur.CreateTime != 0 && pp.CreateTime > cur.CreateTime {
			break // created after its "child": a reused PID
		}
		img, _ := ImagePath(pp.PID)
		out = append(out, Ancestor{PID: pp.PID, Image: img, CreateTime: pp.CreateTime})
		cur = pp
	}
	return out
}

// RunningImage lists the processes running the executable at path.
func RunningImage(path string) []uint32 {
	snap, err := Snapshot()
	if err != nil {
		return nil
	}
	var out []uint32
	for pid := range snap {
		if pid == 0 || pid == 4 {
			continue
		}
		if img, err := ImagePath(pid); err == nil && samePath(img, path) {
			out = append(out, pid)
		}
	}
	return out
}

func samePath(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
