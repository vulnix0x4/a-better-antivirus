package procinfo

// Every process and thread on the system as the kernel lists them
// (NtQuerySystemInformation, SystemProcessInformation): one call, no handle
// to any process needed. Package instant reads it to find who is stuck inside
// an open of a bait; Browser reads it to tell whether a browser was created
// suspended and never ran.

import (
	"errors"
	"unsafe"
)

// SysThread is one thread as the kernel lists it.
type SysThread struct {
	PID, TID    uint32
	KernelTime  int64  // 100 ns units
	UserTime    int64  // 100 ns units: time spent running its own (user-mode) code
	CreateTime  int64  // FILETIME
	WaitTime    uint32 // tick count when its current wait began
	CtxSwitches uint32
	State       uint32 // ThreadState: 5 = waiting
	WaitReason  uint32 // KWAIT_REASON: 0 = Executive, 5 = Suspended
}

// SysProcess is one process as the kernel lists it, with its threads.
type SysProcess struct {
	PID, PPID  uint32
	CreateTime int64
	Threads    []SysThread
}

// Thread states and wait reasons (KTHREAD_STATE, KWAIT_REASON).
const (
	ThreadWaiting     = 5
	WaitExecutive     = 0
	WaitSuspended     = 5
	statusInfoLenMism = 0xC0000004
	systemProcessInfo = 5

	// x64 / arm64 layouts of SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION.
	spiSize       = 0x100
	spiThreads    = 0x04
	spiCreateTime = 0x20
	spiPID        = 0x50
	spiPPID       = 0x58
	stiSize       = 0x50
	stiKernelTime = 0x00
	stiUserTime   = 0x08
	stiCreateTime = 0x10
	stiWaitTime   = 0x18
	stiTID        = 0x30
	stiCtxSwitch  = 0x40
	stiState      = 0x44
	stiWaitReason = 0x48
)

// SystemProcesses lists the processes keep accepts (nil: all), with their
// threads, in the order the kernel keeps them: a process's first thread
// first.
func SystemProcesses(keep func(pid uint32) bool) ([]SysProcess, error) {
	size := uint32(1 << 20)
	var buf []byte
	for i := 0; ; i++ {
		buf = make([]byte, size)
		var ret uint32
		r, _, _ := procNtQuerySystemInformation.Call(systemProcessInfo, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		if r == 0 {
			break
		}
		if uint32(r) != statusInfoLenMism || i > 6 {
			return nil, errors.New("NtQuerySystemInformation failed")
		}
		size *= 2
		if ret > size {
			size = ret + 64<<10
		}
	}
	var out []SysProcess
	for off := 0; off+spiSize <= len(buf); {
		base := buf[off:]
		next := le32(base, 0)
		pid := uint32(le64(base, spiPID))
		if keep == nil || keep(pid) {
			p := SysProcess{PID: pid, PPID: uint32(le64(base, spiPPID)), CreateTime: int64(le64(base, spiCreateTime))}
			n := int(le32(base, spiThreads))
			for i := 0; i < n && spiSize+(i+1)*stiSize <= len(base); i++ {
				t := base[spiSize+i*stiSize:]
				p.Threads = append(p.Threads, SysThread{PID: pid, TID: uint32(le64(t, stiTID)),
					KernelTime: int64(le64(t, stiKernelTime)), UserTime: int64(le64(t, stiUserTime)), CreateTime: int64(le64(t, stiCreateTime)),
					WaitTime: le32(t, stiWaitTime), CtxSwitches: le32(t, stiCtxSwitch), State: le32(t, stiState), WaitReason: le32(t, stiWaitReason)})
			}
			out = append(out, p)
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out, nil
}

func le32(b []byte, off int) uint32 { return *(*uint32)(unsafe.Pointer(&b[off])) }
func le64(b []byte, off int) uint64 { return *(*uint64)(unsafe.Pointer(&b[off])) }

// FirstThread is the thread a process was created with: the oldest one (the
// kernel lists threads oldest first, which settles a tie).
func (p SysProcess) FirstThread() (SysThread, bool) {
	if len(p.Threads) == 0 {
		return SysThread{}, false
	}
	first := p.Threads[0]
	for _, t := range p.Threads[1:] {
		if t.CreateTime < first.CreateTime {
			first = t
		}
	}
	return first, true
}

// NeverRan reports whether t looks suspended without ever having run code of
// its own: it waits because it's suspended, and the kernel never counted any
// time running its program's code. (That count goes by clock ticks, so a
// thread that ran only a few milliseconds before being suspended can show
// none either: CreatedSuspended also looks at where the thread is.)
func (t SysThread) NeverRan() bool {
	return t.State == ThreadWaiting && t.WaitReason == WaitSuspended && t.UserTime == 0
}

// CreatedSuspended reports whether pid's first thread was created suspended
// and has never run: it's suspended (see NeverRan) and still sits where every
// thread starts, with the context Windows gave it when it was created. A
// process ABA (or anything else) suspended after it had run is somewhere in
// its own code by then.
func CreatedSuspended(pid uint32) (bool, error) {
	ps, err := SystemProcesses(func(p uint32) bool { return p == pid })
	if err != nil {
		return false, err
	}
	if len(ps) == 0 {
		return false, ErrGone
	}
	t, ok := ps[0].FirstThread()
	if !ok || !t.NeverRan() {
		return false, nil
	}
	if at, known := atThreadStart(t.TID); known {
		return at, nil
	}
	return true, nil
}
