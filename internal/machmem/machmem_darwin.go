//go:build darwin && cgo

// Package machmem reads another process's memory on macOS, through the Mach
// calls that need cgo (task_for_pid, mach_vm_region, mach_vm_read). It's the
// only package of ABA that uses cgo, and only on macOS.
//
// It works for a process ABA's service (root) may inspect: an ordinary
// program, not one of Apple's and not one built with the hardened runtime
// that forbids it (most stealers are neither). It reads only memory that's
// both readable and writable (the heap, stacks, what the program made),
// never its code or what it mapped read-only from files.
package machmem

/*
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static kern_return_t aba_task(int pid, mach_port_t *task) {
	return task_for_pid(mach_task_self(), pid, task);
}

static kern_return_t aba_region(mach_port_t task, mach_vm_address_t *addr, mach_vm_size_t *size, int *prot, int *shared) {
	vm_region_extended_info_data_t info;
	mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
	mach_port_t object = MACH_PORT_NULL;
	kern_return_t kr = mach_vm_region(task, addr, size, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info, &count, &object);
	if (object != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), object);
	}
	if (kr == KERN_SUCCESS) {
		*prot = info.protection;
		*shared = (info.share_mode == SM_SHARED || info.share_mode == SM_TRUESHARED);
	}
	return kr;
}

static kern_return_t aba_read(mach_port_t task, mach_vm_address_t addr, mach_vm_size_t size, void *buf, mach_vm_size_t *got) {
	return mach_vm_read_overwrite(task, addr, size, (mach_vm_address_t)buf, got);
}

static void aba_done(mach_port_t task) {
	if (task != mach_task_self()) {
		mach_port_deallocate(mach_task_self(), task);
	}
}
*/
import "C"

import (
	"fmt"
)

const chunk = 1 << 20

// Read hands fn the process's private, writable memory, a chunk at a time,
// at most limit bytes in all; fn returns false to stop. It returns how many
// bytes were read.
func Read(pid uint32, limit int64, fn func(base uint64, b []byte) bool) (int64, error) {
	var task C.mach_port_t
	if kr := C.aba_task(C.int(pid), &task); kr != C.KERN_SUCCESS {
		return 0, fmt.Errorf("macOS won't let ABA look into process %d (task_for_pid: %d): it may be one of Apple's, or built with the hardened runtime", pid, int(kr))
	}
	defer C.aba_done(task)
	buf := C.malloc(chunk)
	defer C.free(buf)
	var total int64
	addr := C.mach_vm_address_t(0)
	for {
		var size C.mach_vm_size_t
		var prot, shared C.int
		if C.aba_region(task, &addr, &size, &prot, &shared) != C.KERN_SUCCESS {
			break
		}
		const want = C.VM_PROT_READ | C.VM_PROT_WRITE
		if prot&want == want && shared == 0 {
			for off := C.mach_vm_size_t(0); off < size; off += chunk {
				n := size - off
				if n > chunk {
					n = chunk
				}
				if total+int64(n) > limit {
					return total, nil
				}
				var got C.mach_vm_size_t
				if C.aba_read(task, addr+C.mach_vm_address_t(off), n, buf, &got) != C.KERN_SUCCESS || got == 0 {
					break
				}
				total += int64(got)
				if !fn(uint64(addr)+uint64(off), C.GoBytes(buf, C.int(got))) {
					return total, nil
				}
			}
		}
		addr += C.mach_vm_address_t(size)
	}
	return total, nil
}
