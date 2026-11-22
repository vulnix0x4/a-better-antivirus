// Copyright (c) 2021 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// arena is a bump allocation arena that returns memory from the non-Go heap.
// It exists because calling into the WFP API requires allocating
// structs on the C heap and knitting them into nested structs, and
// tracking individual allocations and their matching frees dirties
// the APIs. Instead, top-level API functions create an arena, and all
// subordinate allocations come out of that managed-lifetime pool.
type arena struct {
	slabs     []uintptr
	next      uintptr
	remaining uintptr
}

const slabSize = 4096

// allocAlign is the alignment of everything Alloc returns: that of the most
// strictly aligned field in the structs it holds (pointers, uint64s).
const allocAlign = 8

// grow adds a new slab to the allocator and handles future calls to
// alloc/calloc out of it.
func (a *arena) grow() {
	slab, err := windows.LocalAlloc(windows.LPTR, slabSize)
	if err != nil {
		panic(fmt.Sprintf("memory allocation failed: %v", err))
	}
	a.slabs = append(a.slabs, slab)
	a.next = slab
	a.remaining = slabSize
}

// Alloc returns an unsafe.Pointer to a zeroed range of length bytes.
func (a *arena) Alloc(length uintptr) unsafe.Pointer {
	if length > slabSize {
		panic(fmt.Sprintf("can't allocate something that big (%d bytes)", length))
	}
	if length == 0 {
		panic("can't allocate zero bytes")
	}
	// Keep every allocation pointer-aligned. Strings take an even but
	// otherwise arbitrary number of bytes, so without this the struct
	// allocated after one can start at an address that isn't a multiple
	// of 8. Copying a struct that holds pointers there (*ret = fwpmFilter0{...})
	// goes through the garbage collector's write barrier while a GC is
	// running, and the runtime throws "bulkBarrierPreWrite: unaligned
	// arguments", killing the process. (Patched in a-better-antivirus.)
	length = (length + allocAlign - 1) &^ (allocAlign - 1)
	if length > a.remaining {
		a.grow()
	}

	// Cast from *uintptr rather than plain uintptr to avoid the go
	// vet unsafe.Pointer safety check. This pattern is safe because
	// a.next never points into the Go heap.
	ret := *(**struct{})(unsafe.Pointer(&a.next))
	a.next += length
	a.remaining -= length
	return unsafe.Pointer(ret)
}

// Dispose frees all the memory returned by prior Alloc calls.
// The arena can continue to be used after a call to Dispose.
func (a *arena) Dispose() {
	for _, slab := range a.slabs {
		if _, err := windows.LocalFree(windows.Handle(slab)); err != nil {
			panic(fmt.Sprintf("free failed: %v", err))
		}
	}
	a.slabs = a.slabs[:0]
	a.next = 0
	a.remaining = 0
}
